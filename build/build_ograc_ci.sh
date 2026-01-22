#!/bin/bash

set -e

CURRENT_PATH=$(dirname $(readlink -f $0))
source "${CURRENT_PATH}"/common.sh

OGDB_CODE_PATH="${CURRENT_PATH}"/..
BUILD_TARGET_NAME="ograc_connector"
BUILD_PACK_NAME="openGauss_oGRAC"
ENV_TYPE=$(uname -p)
TMP_PKG_PATH=${OGDB_CODE_PATH}/package
OGDB_TARGET_PATH=${OGRACDB_BIN}/${BUILD_TARGET_NAME}/ogracKernel
OGRAC_IMAGE="${OGDB_CODE_PATH}/image"

mkdir -p ${TMP_PKG_PATH}

function packageTarget() {
  echo "Start packageTarget..."
  cd "${OGRACDB_BIN}"
  echo "当前目录: $(pwd)"
  echo "目录内容:"
  ls -la
  tar -zcf ograc.tar.gz ${BUILD_TARGET_NAME}/
  if [ -d ${OGRAC_IMAGE} ]; then
    rm -rf ${OGRAC_IMAGE}
  fi
  mkdir -p ${OGRAC_IMAGE}
  mv -f ograc.tar.gz ${OGRAC_IMAGE}
  cd ${CURRENT_PATH}
  bash "${CURRENT_PATH}"/rpm_build_ograc.sh
}

function buildCtOmPackage() {
  bash "${CURRENT_PATH}"/build_ograc_om.sh
  bash "${CURRENT_PATH}"/rpm_build_og_om.sh
  if [ $? -ne 0 ]; then
      echo "build og_om fail"
      return 1
  fi
}

function buildDssPackage() {
  sh "${CURRENT_PATH}"/build_dss.sh ${BUILD_TYPE}
}

function newPackageTarget() {
  echo "Start newPackageTarget..."
  local current_time=$(date "+%Y%m%d%H%M%S")
  local pkg_dir_name="${BUILD_TARGET_NAME}"
  local build_type_upper=$(echo "${BUILD_TYPE}" | tr [:lower:] [:upper:])
  if [[ ${COMPILE_TYPE} == "ASAN" ]]; then
    build_type_upper="${COMPILE_TYPE}"
  fi
  local pkg_name="${BUILD_PACK_NAME}_${ENV_TYPE}_${build_type_upper}.tgz"
  if [[ ${BUILD_MODE} == "single" ]]; then
    pkg_name="${BUILD_PACK_NAME}_${BUILD_MODE}_${ENV_TYPE}_${build_type_upper}.tgz"
  fi
  local pkg_real_path=${TMP_PKG_PATH}/${pkg_dir_name}
  echo "当前目录: $(pwd)"
  echo "目录内容:"
  ls -la
  mkdir -p ${pkg_real_path}/{action,repo,config,common,dss}
  B_VERSION=$(grep -oP '<Bversion>\K[^<]+' "${OGDB_CODE_PATH}"/../ProductComm_DoradoAA/CI/conf/cmc/dbstore/archive_cmc_versions.xml | sed 's/oGRAC //g')
  # 提取B_VERSION最后一个点之后的部分
  B_VERSION_SUFFIX="${B_VERSION##*.}"
  echo "B_VERSION_SUFFIX: ${B_VERSION_SUFFIX}"
  if [[ x"${B_VERSION}" != x"" ]];then
      # 替换versions.yml 中的版本号的最后一个点后的部分
      sed -i "s/\(Version: .*\)\.[A-Z].*/\1.${B_VERSION_SUFFIX}/" "${CURRENT_PATH}"/versions.yml
  fi
  sed -i 's#ChangeVersionTime: .*#ChangeVersionTime: '"$(date +%Y/%m/%d\ %H:%M)"'#' "${CURRENT_PATH}"/versions.yml
  echo "当前目录: $(pwd)"
  echo "目录内容:"
  ls -la
  cp -arf "${CURRENT_PATH}"/versions.yml ${pkg_real_path}/
  cp -arf "${OGRACDB_BIN}"/rpm/RPMS/"${ENV_TYPE}"/ograc*.rpm ${pkg_real_path}/repo/
  cp -arf "${OGDB_CODE_PATH}"/temp/og_om/rpm/RPMS/"${ENV_TYPE}"/og_om*.rpm ${pkg_real_path}/repo/
  cp -arf "${OGDB_CODE_PATH}"/pkg/deploy/action/* ${pkg_real_path}/action/
  cp -arf "${OGDB_CODE_PATH}"/pkg/deploy/config/* ${pkg_real_path}/config/
  cp -arf "${OGDB_CODE_PATH}"/common/* ${pkg_real_path}/common/
  if [[ ${BUILD_MODE} == "single" ]]; then
    cp -rf "${OGDB_CODE_PATH}"/pkg/deploy/single_options/* ${pkg_real_path}/action/oGRAC
  fi
  cp -arf "${OGDB_CODE_PATH}"/dss/* ${pkg_real_path}/dss/
  echo "目录内容:"

  sed -i "/main \$@/i CSTOOL_TYPE=${BUILD_TYPE}" ${pkg_real_path}/action/dbstor/check_usr_pwd.sh
  sed -i "/main \$@/i CSTOOL_TYPE=${BUILD_TYPE}" ${pkg_real_path}/action/dbstor/check_dbstor_compat.sh
  sed -i "/main \$@/i CSTOOL_TYPE=${BUILD_TYPE}" ${pkg_real_path}/action/inspection/inspection_scripts/kernal/check_link_cnt.sh

  echo "Start pkg ${pkg_name}..."
  cd ${TMP_PKG_PATH}
  echo "当前目录: $(pwd)"
  echo "目录内容:"
  ls -la
  tar -zcf "${pkg_name}" ${pkg_dir_name}
  rm -rf ${TMP_PKG_PATH}/${pkg_dir_name}
  rm -rf ${pkg_dir_name}
  echo "Packing ${pkg_name} success"
}

function seperateSymbol() {
  so_path=$1
  sh "${CURRENT_PATH}"/seperate_dbg_symbol.sh ${so_path}
}

function prepare_path() {
  cd ${WORKSPACE}
  mkdir -p oGRAC/build_dependence/libaio/include/
  cp libaio.h oGRAC/build_dependence/libaio/include/
  cd -
}

function prepare() {
  prepare_path

  if [[ ${BUILD_MODE} == "multiple" ]] || [[ -z ${BUILD_MODE} ]]; then
    echo "compiling multiple process"
    if [[ ${BUILD_TYPE} == "debug" ]]; then
      if [[ ${COMPILE_TYPE} == "ASAN" ]]; then
        echo "compiling multiple process asan"
        sh "${CURRENT_PATH}"/Makefile_ci.sh "${OG_BUILD_TYPE} asan=1"
      else
        echo "compiling multiple process debug"
        sh "${CURRENT_PATH}"/Makefile_ci.sh "${OG_BUILD_TYPE}"
      fi
    else
      echo "compiling multiple process release"
      sh "${CURRENT_PATH}"/Makefile_ci.sh "${OG_BUILD_TYPE}"
    fi
  elif [[ ${BUILD_MODE} == "single" ]]; then
    echo "compiling single process"
    if [[ ${BUILD_TYPE} == "debug" ]]; then
      if [[ ${COMPILE_TYPE} == "ASAN" ]]; then
        echo "compiling single process asan"
        sh "${CURRENT_PATH}"/Makefile_ci.sh "${OG_BUILD_TYPE} asan=1"
      else
        echo "compiling single process debug"
        sh "${CURRENT_PATH}"/Makefile_ci.sh "${OG_BUILD_TYPE}"
      fi
    else
      echo "compiling single process release"
      sh "${CURRENT_PATH}"/Makefile_ci.sh "${OG_BUILD_TYPE}"
    fi
  else
    echo "unsupported build mode"
    exit 1
  fi

  if [ ! -d "${OGDB_TARGET_PATH}" ];then
    mkdir -p "${OGDB_TARGET_PATH}"
    chmod 700 "${OGDB_TARGET_PATH}"
  fi
  cp -arf "${OGDB_CODE_PATH}"/oGRAC-DATABASE* "${OGDB_TARGET_PATH}"/
}

BUILD_TYPE=${1,,}
if [[ ${BUILD_TYPE} != "debug" ]] && [[ ${BUILD_TYPE} != "release" ]]; then
  echo "Usage: ${0##*/} {debug|release}."
  exit 0
fi

OG_BUILD_TYPE="package-${BUILD_TYPE}"

prepare
buildCtOmPackage
packageTarget
buildDssPackage
newPackageTarget
