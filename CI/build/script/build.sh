#!/bin/bash

set -ex
source /etc/profile
BUILD_TYPE=${BUILD_TYPE:-"DEBUG"}
ENV_TYPE=${ENV_TYPE:-"x86_64"}
BUILD_MODE=${BUILD_MODE:-"multiple"}
if [ "${WORKSPACE}" != "" ]; then
    HOME_PATH=${WORKSPACE}
    OGDB_CODE_PATH=${HOME_PATH}/oGRAC
    ln -s ${OGDB_CODE_PATH} /home/regress/ogracKernel
 
else
    HOME_PATH="/home/regress"
    OGDB_CODE_PATH=${HOME_PATH}/ogracKernel
fi
CI_PACKAGE_PATH=${OGDB_CODE_PATH}/package_out
BUILD_TARGET_NAME="ograc_connector"
BUILD_PACK_NAME="openGauss_oGRAC"
SYMBOL_TARGET_NAME="ograc_connector_symbol"
BUILD_TARGET_PATH=${CI_PACKAGE_PATH}/${BUILD_TARGET_NAME}
BUILD_SYMBOL_PATH=${CI_PACKAGE_PATH}/${SYMBOL_TARGET_NAME}
OGDB_TARGET_PATH=${BUILD_TARGET_PATH}/ogracKernel
XNET_LIB_PATH=${OGDB_CODE_PATH}/library/xnet/lib
BOOST_PATH=/tools/boost_1_73_0
OGRAC_LIB_DIR=${OGDB_CODE_PATH}/oGRAC_lib
OGRAC_SECURITY_LIB_PATH=${OGDB_CODE_PATH}/library/huawei_security/lib
LLT_TEST_TYPE=${1}
FEATURE_FOR_EVERSQL=${FEATURE_FOR_EVERSQL:-"0"}
OS_ARCH=$(uname -i)
if [[ ${OS_ARCH} =~ "x86_64" ]]; then
    export CPU_CORES_NUM=`cat /proc/cpuinfo |grep "cores" |wc -l`
    LIB_OS_ARCH="lib_x86"
elif [[ ${OS_ARCH} =~ "aarch64" ]]; then 
    export C_INCLUDE_PATH=:/usr/include/python3.7m/
    CPU_CORES_NUM=`cat /proc/cpuinfo |grep "architecture" |wc -l`
    LIB_OS_ARCH="lib_arm"
else 
    echo "OS_ARCH: ${OS_ARCH} is unknown, set CPU_CORES_NUM=16 "
    CPU_CORES_NUM=16
fi

CURRENT_PATH=$(dirname $(readlink -f $0))

SCRIPT_TOP_DIR=$(cd ${CURRENT_PATH}; pwd)
CI_TOP_DIR=$(cd ${SCRIPT_TOP_DIR}/..; pwd)
TMP_PKG_PATH=/tmp/oGRAC_new
TMP_COPY_PKG_NAME="${BUILD_TARGET_NAME}_for_asan"
TMP_COPY_PKG_TARGET="${BUILD_TARGET_NAME}_for_asan.tgz"

echo "Start build..."
echo "BUILD_TYPE: ${BUILD_TYPE}"
echo "ENV_TYPE: ${ENV_TYPE}"
echo "BUILD_MODE: ${BUILD_MODE}"
echo "HOME_PATH: ${HOME_PATH}"
echo "BUILD_TARGET_PATH: ${BUILD_TARGET_PATH}"
echo "LLT_TEST_TYPE: ${LLT_TEST_TYPE}"  # 当跑门禁测试用例的时候，传"ASAN"或者"GCOV"
echo "B_VERSION: ${B_VERSION}"   # 门禁通过传递参数修改versions.yaml的B版本

CURRENT_DIR=$(dirname $(readlink -f "$0"))
source ${CURRENT_DIR}/../../../build/function.sh

function collectoGRACTarget() {
  echo "Start collectoGRACTarget..."

  rm -rf ${OGDB_TARGET_PATH}
  mkdir -p ${OGDB_TARGET_PATH}
  cp -arf ${OGDB_CODE_PATH}/output/bin/oGRAC-DATABASE-CENTOS-64bit ${OGDB_TARGET_PATH}
  cp -arf ${OGDB_CODE_PATH}/output/bin/oGRAC-DATABASE-CENTOS-64bit.sha256 ${OGDB_TARGET_PATH}
  if [ "${BUILD_TYPE}" == "RELEASE" ] && [ "${COMPILE_TYPE}" != "ASAN" ]; then
    cp -arf ${OGDB_CODE_PATH}/output/bin/oGRAC-DATABASE-CENTOS-64bit-SYMBOL ${BUILD_SYMBOL_PATH}
    cp -arf ${OGDB_CODE_PATH}/output/bin/oGRAC-DATABASE-CENTOS-64bit-SYMBOL.sha256 ${BUILD_SYMBOL_PATH}
  fi
}

function collectTarget() {
  echo "Start collectTarget..."
  collectoGRACTarget
}

function generateScmFile() {
  echo "Start generateScmFile..."
  cd ${BUILD_TARGET_PATH}
  local scm_file_name="scm.property"
  rm -f ${scm_file_name}
  current_time=$(date "+%Y%m%d%H%M%S")
  # 获取当前时间戳
  echo "Package Time: ${current_time}" >>${scm_file_name}
  cd ${OGDB_CODE_PATH}
  local oGRAC_commit_id=$(git rev-parse HEAD)
  cd -
  echo "Commit Id:" >>${scm_file_name}
  echo "    oGRAC: ${oGRAC_commit_id}" >>${scm_file_name}
  echo "scm info："
  cat ${scm_file_name}
}

function packageTarget() {
  echo "Start packageTarget..."
  echo "当前目录: $(pwd)"
  echo "目录内容:"
  ls -la
  cd ${CI_PACKAGE_PATH}
  tar -zcf ograc.tar.gz ${BUILD_TARGET_NAME}/
  if [ -d /opt/ograc/image ]; then
    rm -rf /opt/ograc/image
  fi
  mkdir -p /opt/ograc/image
  mv -f ograc.tar.gz /opt/ograc/image/
  sh ${CURRENT_PATH}/rpm_build_ograc.sh
  cd -
}

function newPackageTarget() {
  echo "Start newPackageTarget..."
  local current_time=$(date "+%Y%m%d%H%M%S")
  local pkg_dir_name="${BUILD_TARGET_NAME}"
  local pkg_name="${BUILD_PACK_NAME}_${ENV_TYPE}_${BUILD_TYPE}_${current_time}.tgz"
  local symbol_pkg_name="${SYMBOL_TARGET_NAME}_${ENV_TYPE}_${BUILD_TYPE}_${current_time}.tgz"
  if [ "${BUILD_MODE}" == "single" ]; then
    pkg_name="${BUILD_PACK_NAME}_${BUILD_MODE}_${ENV_TYPE}_${BUILD_TYPE}_${current_time}.tgz"
    symbol_pkg_name="${SYMBOL_TARGET_NAME}_${BUILD_MODE}_${ENV_TYPE}_${BUILD_TYPE}_${current_time}.tgz"
  fi
  if [ "${BUILD_MODE}" == "multiple" ] && [ "${COMPILE_TYPE}" == "ASAN" ]; then
    pkg_name="${BUILD_PACK_NAME}_${ENV_TYPE}_${COMPILE_TYPE}_${current_time}.tgz"
  fi  
  if [ "${BUILD_TYPE}" == "RELEASE" ] && [ "${BUILD_MODE}" == "single" ]; then
    pkg_name="${BUILD_PACK_NAME}_${BUILD_MODE}_${ENV_TYPE}_${BUILD_TYPE}.tgz"
  fi
  if [ "${BUILD_TYPE}" == "RELEASE" ] && [ "${BUILD_MODE}" == "multiple" ] && [ "${COMPILE_TYPE}" != "ASAN" ]; then
    pkg_name="${BUILD_PACK_NAME}_${ENV_TYPE}_${BUILD_TYPE}.tgz"
  fi
  local pkg_real_path=${TMP_PKG_PATH}/${pkg_dir_name}
  if [ -d ${pkg_real_path} ]; then
    rm -rf ${pkg_real_path}
  fi
  mkdir -p ${pkg_real_path}/action
  mkdir -p ${pkg_real_path}/repo
  mkdir -p ${pkg_real_path}/config
  mkdir -p ${pkg_real_path}/common
  if [[ x"${B_VERSION}" != x"" ]];then
      sed -i "s/B[0-9]\+/${B_VERSION}/g" ${OGDB_CODE_PATH}/CI/build/conf/versions.yml
  fi
  cp -arf ${OGDB_CODE_PATH}/CI/build/conf/versions.yml ${pkg_real_path}/
  cp -f ${CURRENT_PATH}/rpm/RPMS/${ENV_TYPE}/ograc*.rpm ${pkg_real_path}/repo/
  cp -f ${CI_TOP_DIR}/temp/og_om/rpm/RPMS/${ENV_TYPE}/og_om*.rpm ${pkg_real_path}/repo
  cp -rf ${CI_TOP_DIR}/../../pkg/deploy/action/* ${pkg_real_path}/action/
  cp -rf ${CI_TOP_DIR}/../../pkg/deploy/config/* ${pkg_real_path}/config/
  cp -rf ${CI_TOP_DIR}/../../common/* ${pkg_real_path}/common/
  if [ "${BUILD_MODE}" == "single" ]; then
      cp -rf ${CI_TOP_DIR}/../../pkg/deploy/single_options/* ${pkg_real_path}/action/oGRAC
  fi

  # 在脚本中调用 main 函数之前添加变量，区分 debug release asan版本
  if [ "${COMPILE_TYPE}" == "ASAN" ]; then
      sed -i "/main \$@/i CSTOOL_TYPE=${COMPILE_TYPE,,}" ${pkg_real_path}/action/dbstor/check_usr_pwd.sh
      sed -i "/main \$@/i CSTOOL_TYPE=${COMPILE_TYPE,,}" ${pkg_real_path}/action/dbstor/check_dbstor_compat.sh
      sed -i "/main \$@/i CSTOOL_TYPE=${COMPILE_TYPE,,}" ${pkg_real_path}/action/inspection/inspection_scripts/kernal/check_link_cnt.sh
  else
      sed -i "/main \$@/i CSTOOL_TYPE=${BUILD_TYPE,,}" ${pkg_real_path}/action/dbstor/check_usr_pwd.sh
      sed -i "/main \$@/i CSTOOL_TYPE=${BUILD_TYPE,,}" ${pkg_real_path}/action/dbstor/check_dbstor_compat.sh
      sed -i "/main \$@/i CSTOOL_TYPE=${BUILD_TYPE,,}" ${pkg_real_path}/action/inspection/inspection_scripts/kernal/check_link_cnt.sh
  fi

  if [ "${static_type}" != "cooddy" ]; then
    echo "Start pkg ${pkg_dir_name}.tgz..."
    cd ${TMP_PKG_PATH}
    tar -zcf ${pkg_name} ${pkg_dir_name}
    cp ${pkg_name} ${CI_PACKAGE_PATH}/

    if [ "${BUILD_TYPE}" == "RELEASE" ] && [ "${COMPILE_TYPE}" != "ASAN" ]; then
      # oGRAC符号表单独编包
      cd ${CI_PACKAGE_PATH}
      tar -zcf ${symbol_pkg_name} ${SYMBOL_TARGET_NAME}/
      mkdir -p ${CI_PACKAGE_PATH}/${TMP_COPY_PKG_NAME}
      cp -f ${CI_PACKAGE_PATH}/${pkg_name} ${CI_PACKAGE_PATH}/${TMP_COPY_PKG_NAME}/${TMP_COPY_PKG_TARGET}
    fi
  fi
}

function buildoGRACDebug() {
  echo "Start buildoGRACDebug..."
  cd ${OGDB_CODE_PATH}/build
  if [ "${BUILD_MODE}" == "multiple" ]; then
    sh Makefile.sh package
  elif [ "${BUILD_MODE}" == "single" ]; then
    sh Makefile.sh package
  fi
  cd -
}

function buildoGRACAsan() {
  echo "Start buildoGRACAsan..."
  cd ${OGDB_CODE_PATH}/build
  if [ "${BUILD_MODE}" == "multiple" ]; then
    sh Makefile.sh package-release asan=1
  elif [ "${BUILD_MODE}" == "single" ]; then
    sh Makefile.sh package-release asan=1
  fi
  cd -
}

function buildoGRACRelease() {
  echo "Start buildoGRACRelease..."
  cd ${OGDB_CODE_PATH}/build
  if [ "${BUILD_MODE}" == "multiple" ]; then
    sh -x Makefile.sh package-release
  elif [ "${BUILD_MODE}" == "single" ]; then
    sh -x Makefile.sh package-release
  fi
  cd -
}

function prepare() {
  # 合并不同代码仓代码至oGRAC目录

  if [ -L ${OGDB_CODE_PATH} ]; then
    rm -f ${OGDB_CODE_PATH}
  fi
  local code_home=$(dirname $(realpath ${BASH_SOURCE[0]}))/../../../..
  echo $(realpath ${BASH_SOURCE[0]})
  ln -s -f ${code_home}/oGRAC ${OGDB_CODE_PATH}
  rm -rf ${BUILD_TARGET_PATH}
  mkdir -p ${BUILD_TARGET_PATH}
  generateScmFile

  local xml_path=/etc/maven/settings.xml
  local GCC_VERSION=`gcc --version |head -1 |awk '{print $NF}'`
  if [[ ${OS_ARCH} =~ "aarch64" ]] && ([[ ${GCC_VERSION} == "10.3.1" ]] || [[ ${GCC_VERSION} == "7.3.0" ]]); then
      xml_path=$MAVEN_HOME/conf/settings.xml
  fi
  rm -f ${xml_path}
  cp ${OGDB_CODE_PATH}/CI/maven/settings.xml ${xml_path}
  if [[ ${OS_ARCH} =~ "x86_64" ]]; then
      xml_path=$MAVEN_HOME/conf/settings.xml
  fi
  rm -f ${xml_path}
  cp ${OGDB_CODE_PATH}/CI/maven/settings.xml ${xml_path}
}


function buildCtOmPackage() {
  sh ${CURRENT_PATH}/build_ograc_om.sh
  sh ${CURRENT_PATH}/rpm_build_og_om.sh
  if [ $? -ne 0 ]; then
      echo "build og_om fail"
      retrun 1
  fi

}

function installCert(){

    local cert_home=$JAVA_HOME/jre/lib/security
    local GCC_VERSION=`gcc --version |head -1 |awk '{print $NF}'`
    if [[ ${OS_ARCH} =~ "aarch64" ]] && [[ ${GCC_VERSION} == "10.3.1" ]]; then
        # v2R11 该路径与其他版本有区别，由于老镜像用的是混合镜像(v2r11内核)，这里用gcc -v区分
        cert_home=$JAVA_HOME/lib/security
    fi
    cd ${cert_home}
    keytool -keystore cacerts -importcert -alias HuaweiITRootCA -file HuaweiITRootCA.cer -storepass changeit -noprompt
    keytool -keystore cacerts -importcert -alias HWITEnterpriseCA1 -file HWITEnterpriseCA1.cer -storepass changeit -noprompt
    chmod 755 -R ${cert_home}/cacerts
    # cd -
}

set +e

set -e
prepare
if [ "${BUILD_MODE}" == "multiple" ] && [ "${COMPILE_TYPE}" == "ASAN" ]; then
  buildoGRACAsan
  buildCtOmPackage
elif [ "${BUILD_TYPE}" == "DEBUG" ]; then
  buildoGRACDebug
  buildCtOmPackage
elif [ "${BUILD_TYPE}" == "RELEASE" ]; then
  buildoGRACRelease
  buildCtOmPackage
else
  echo "BUILD_TYPE: ${BUILD_TYPE} or ${COMPILE_TYPE}/${BUILD_MODE} is invalid!"
  exit 1
fi

# ASAN， GCOV 门禁使用参数，跑门禁不需要打包
if [ "${LLT_TEST_TYPE}" == "ASAN" ] || [ "${LLT_TEST_TYPE}" == "GCOV" ]; then
  echo "----------------- BUILD.SH FINISH -----------------"
  exit 0
else
  echo "----------------- COLLECTING AND PACKAGING -----------------"
  collectTarget
  packageTarget
  newPackageTarget
fi

if [ "${static_type}" != "cooddy" ]; then
    [[ ! -d ${OGDB_CODE_PATH}/package ]] && mkdir -p ${OGDB_CODE_PATH}/package
    cp ${OGDB_CODE_PATH}/package_out/*.tgz ${OGDB_CODE_PATH}/package/
fi