#!/bin/bash

set -e

CURRENT_PATH=$(dirname $(readlink -f $0))
source "${CURRENT_PATH}"/common.sh

OGDB_CODE_PATH="${CURRENT_PATH}"/..
BUILD_TARGET_NAME="ograc_connector"
BUILD_PACK_NAME="oGRAC 1.0.0"
ENV_TYPE=$(uname -p)
TMP_PKG_PATH=${OGDB_CODE_PATH}/package
OGDB_TARGET_PATH=${OGRACDB_BIN}/${BUILD_TARGET_NAME}/ogracKernel

export INTERNAL_BUILD="TRUE"

if [[ ! -d "${OGDB_CODE_PATH}"/../ProductComm_DoradoAA ]];then
    export INTERNAL_BUILD="FALSE"
fi

if [[ ${INTERNAL_BUILD} == "TRUE" ]];then
    TMP_PKG_PATH=${OGDB_CODE_PATH}/package
else
    TMP_PKG_PATH=/tmp/oGRAC_output
fi

mkdir -p ${TMP_PKG_PATH}

function packageTarget() {
  echo "Start packageTarget..."
  cd "${OGRACDB_BIN}"
  tar -zcf ograc.tar.gz ${BUILD_TARGET_NAME}/
  if [ -d /opt/ograc/image ]; then
    rm -rf /opt/ograc/image
  fi
  mkdir -p /opt/ograc/image
  mv -f ograc.tar.gz /opt/ograc/image/
  cd ${CURRENT_PATH}
  bash "${CURRENT_PATH}"/rpm_build_ograc.sh
}

function buildCtOmPackage() {
  bash "${CURRENT_PATH}"/build_ct_om.sh
  bash "${CURRENT_PATH}"/rpm_build_ct_om.sh
  if [ $? -ne 0 ]; then
      echo "build og_om fail"
      return 1
  fi
}

function newPackageTarget() {
  echo "Start newPackageTarget..."
  local current_time=$(date "+%Y%m%d%H%M%S")
  local pkg_dir_name="${BUILD_TARGET_NAME}"
  local build_type_upper=$(echo "${BUILD_TYPE}" | tr [:lower:] [:upper:])
  local pkg_name="${BUILD_PACK_NAME}_${ENV_TYPE}_${build_type_upper}.tgz"


  if [[ ${BUILD_MODE} == "single" ]]; then
    pkg_name="${BUILD_PACK_NAME}_${BUILD_MODE}_${ENV_TYPE}_${build_type_upper}.tgz"
  fi
  local pkg_real_path=${TMP_PKG_PATH}/${pkg_dir_name}
  rm -rf ${TMP_PKG_PATH}/*

  mkdir -p ${pkg_real_path}/{action,repo,config,common,zlogicrep}
  mkdir -p ${pkg_real_path}/zlogicrep/build/oGRAC_PKG/file

  if [[ ${INTERNAL_BUILD} == "TRUE" ]];then  
    B_VERSION=$(grep -oP '<Bversion>\K[^<]+' "${OGDB_CODE_PATH}"/../ProductComm_DoradoAA/CI/conf/cmc/dbstore/archive_cmc_versions.xml | sed 's/oGRAC //g')
    # 提取B_VERSION最后一个点之后的部分
    B_VERSION_SUFFIX="${B_VERSION##*.}"
    echo "B_VERSION_SUFFIX: ${B_VERSION_SUFFIX}"
    if [[ x"${B_VERSION}" != x"" ]];then
        # 替换versions.yml 中的版本号的最后一个点后的部分
        sed -i "s/\(Version: .*\)\.[A-Z].*/\1.${B_VERSION_SUFFIX}/" "${CURRENT_PATH}"/versions.yml
    fi
    sed -i 's#ChangeVersionTime: .*#ChangeVersionTime: '"$(date +%Y/%m/%d\ %H:%M)"'#' "${CURRENT_PATH}"/versions.yml
  fi
  cp -arf "${CURRENT_PATH}"/versions.yml ${pkg_real_path}/
  cp -arf "${OGRACDB_BIN}"/rpm/RPMS/"${ENV_TYPE}"/ograc*.rpm ${pkg_real_path}/repo/
  cp -arf "${OGDB_CODE_PATH}"/temp/og_om/rpm/RPMS/"${ENV_TYPE}"/og_om*.rpm ${pkg_real_path}/repo
  cp -arf "${OGDB_CODE_PATH}"/pkg/deploy/action/* ${pkg_real_path}/action/
  cp -arf "${OGDB_CODE_PATH}"/pkg/deploy/config/* ${pkg_real_path}/config/
  cp -arf "${OGDB_CODE_PATH}"/common/* ${pkg_real_path}/common/
  cp -arf  "${OGRACDB_BIN}"/connector ${TMP_PKG_PATH}/
  rm -rf "${OGRACDB_BIN}"/connector
  if [[ ${BUILD_MODE} == "single" ]]; then
    cp -rf  "${OGDB_CODE_PATH}"/pkg/deploy/single_options/* ${pkg_real_path}/action/oGRAC
  fi
  if [[ ${INTERNAL_BUILD} == "TRUE" ]];then
    cp -rf ${OGDB_CODE_PATH}/pkg/src/zlogicrep/build/oGRAC_PKG/file/* ${pkg_real_path}/zlogicrep/build/oGRAC_PKG/file/
  fi

  sed -i "/main \$@/i CSTOOL_TYPE=${BUILD_TYPE}" ${pkg_real_path}/action/dbstor/check_usr_pwd.sh
  sed -i "/main \$@/i CSTOOL_TYPE=${BUILD_TYPE}" ${pkg_real_path}/action/dbstor/check_dbstor_compat.sh
  sed -i "/main \$@/i CSTOOL_TYPE=${BUILD_TYPE}" ${pkg_real_path}/action/inspection/inspection_scripts/kernal/check_link_cnt.sh
  echo "Start pkg ${pkg_dir_name}.tgz..."
  cd ${TMP_PKG_PATH}
  tar -zcf "${pkg_name}" ${pkg_dir_name}
  rm -rf ${TMP_PKG_PATH}/${pkg_dir_name}
  echo "Packing ${pkg_name} success"
  rm -rf ${pkg_dir_name}

}

function prepare_path() {
  if [[ ${INTERNAL_BUILD} == "TRUE" ]];then
    cd ${WORKSPACE}
    mkdir -p oGRAC/build_dependence/libaio/include/
    cp libaio.h oGRAC/build_dependence/libaio/include/
    mkdir -p ${WORKSPACE}/3rdPartyPkg
    touch ${WORKSPACE}/3rdPartyPkg/oGRAC3.0.0.zip
    unzip ${WORKSPACE}/ograc-test-oGRAC3.0.0.zip -d ${WORKSPACE}/3rdPartyPkg/
    cp ${WORKSPACE}/3rdPartyPkg/ograc-test-oGRAC3.0.0/* ${WORKSPACE}/3rdPartyPkg/
    cd -
  fi  
}

function prepare() {
  prepare_path

  if [[ ${BUILD_MODE} == "multiple" ]] || [[ -z ${BUILD_MODE} ]]; then
    echo "compiling multiple process"
    if [[ ${BUILD_TYPE} == "debug" ]]; then
      echo "compiling multiple process debug"
      sh "${CURRENT_PATH}"/Makefile.sh "${OG_BUILD_TYPE}"
    else
      echo "compiling multiple process release"
      sh "${CURRENT_PATH}"/Makefile.sh "${OG_BUILD_TYPE}"
    fi
  elif [[ ${BUILD_MODE} == "single" ]]; then
    echo "compiling single process"
    if [[ ${BUILD_TYPE} == "debug" ]]; then
      echo "compiling single process debug"
      sh "${CURRENT_PATH}"/Makefile.sh "${OG_BUILD_TYPE}"
    else
      echo "compiling single process release"
      sh "${CURRENT_PATH}"/Makefile.sh "${OG_BUILD_TYPE}"
    fi
  else
    echo "unsupported build mode"
    exit 1
  fi

  if [ ! -d "${OGDB_TARGET_PATH}" ];then
    mkdir -p "${OGDB_TARGET_PATH}"
    chmod 700  "${OGDB_TARGET_PATH}"
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
newPackageTarget
