#!/bin/bash

set -e

CURRENT_PATH=$(dirname $(readlink -f $0))
source "${CURRENT_PATH}"/common.sh

OGDB_CODE_PATH="${CURRENT_PATH}"/..
BUILD_TARGET_NAME="ograc_connector"
BUILD_PACK_NAME="oGRAC"
ENV_TYPE=$(uname -p)
TMP_PKG_PATH=${OGDB_CODE_PATH}/package
OGDB_TARGET_PATH=${OGRACDB_BIN}/${BUILD_TARGET_NAME}/ogracKernel
DSSENABLED="FALSE"
OGRAC_IMAGE="${OGDB_CODE_PATH}/image"

mkdir -p ${TMP_PKG_PATH}

function packageTarget() {
  echo "Start packageTarget..."
  cd "${OGRACDB_BIN}"
  echo "Current directory: $(pwd)"
  ls -la
  tar -zcf ograc.tar.gz ${BUILD_TARGET_NAME}/
  if [ -d ${OGRAC_IMAGE} ]; then
    rm -rf ${OGRAC_IMAGE}
  fi
  mkdir -p ${OGRAC_IMAGE}
  mv -f ograc.tar.gz ${OGRAC_IMAGE}
  cd ${CURRENT_PATH}
  bash "${CURRENT_PATH}"/packet_build_ograc.sh
}

function buildCtOmPackage() {
  bash "${CURRENT_PATH}"/build_ograc_om.sh
  bash "${CURRENT_PATH}"/packet_build_og_om.sh
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
  local ograc_version=$(grep 'Version:' "${CURRENT_PATH}"/versions.yml | awk '{print $2}')
  local build_type_suffix=""
  if [[ ${BUILD_TYPE} == "debug" ]]; then
    build_type_suffix="-debug"
  fi
  local os_distro_part="${OS_DISTRO_NAME}"
  if [[ -z "${os_distro_part}" ]]; then
    os_distro_part=$(echo "${OS_SUFFIX}" | tr '[:upper:]' '[:lower:]')
  fi
  local pkg_name="${BUILD_PACK_NAME}-${ograc_version}"
  if [[ -n "${os_distro_part}" ]]; then
    pkg_name="${pkg_name}-${os_distro_part}"
  fi
  if [[ ${BUILD_MODE} == "single" ]]; then
    pkg_name="${pkg_name}-${BUILD_MODE}"
  fi
  pkg_name="${pkg_name}${build_type_suffix}-${ENV_TYPE}.tgz"
  local pkg_real_path=${TMP_PKG_PATH}/${pkg_dir_name}
  echo "Current directory: $(pwd)"
  ls -la
  mkdir -p ${pkg_real_path}/{action,repo,config,common,dss,odbc}
  cp -arf "${CURRENT_PATH}"/versions.yml ${pkg_real_path}/
  cp -arf "${OGRACDB_BIN}"/ograc*.tar.gz ${pkg_real_path}/repo/
  cp -arf "${OGDB_CODE_PATH}"/temp/og_om/og_om*.tar.gz ${pkg_real_path}/repo/
  cp -arf "${OGDB_CODE_PATH}"/pkg/deploy/action/* ${pkg_real_path}/action/
  cp -arf "${OGDB_CODE_PATH}"/pkg/deploy/config/* ${pkg_real_path}/config/
  cp -arf "${OGDB_CODE_PATH}"/common/* ${pkg_real_path}/common/
  cp -arf "${OGDB_CODE_PATH}"/output/lib/libogodbc.so ${pkg_real_path}/odbc/
  if [[ ${BUILD_MODE} == "single" ]]; then
    cp -rf "${OGDB_CODE_PATH}"/pkg/deploy/single_options/* ${pkg_real_path}/action/oGRAC
  fi
  if [[ ${DSSENABLED} == "TRUE" ]]; then
    cp -arf "${OGDB_CODE_PATH}"/dss/* ${pkg_real_path}/dss/
  fi

  sed -i "/main \$@/i CSTOOL_TYPE=${BUILD_TYPE}" ${pkg_real_path}/action/storage_deploy/dbstor/check_usr_pwd.sh
  sed -i "/main \$@/i CSTOOL_TYPE=${BUILD_TYPE}" ${pkg_real_path}/action/storage_deploy/dbstor/check_dbstor_compat.sh
  sed -i "/main \$@/i CSTOOL_TYPE=${BUILD_TYPE}" ${pkg_real_path}/action/storage_deploy/inspection/inspection_scripts/kernal/check_link_cnt.sh
  echo "Start pkg ${pkg_name}..."
  # Clean Python bytecode cache before packaging
  find ${pkg_real_path} -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
  find ${pkg_real_path} -name "*.pyc" -delete 2>/dev/null || true
  find ${pkg_real_path} -name "*.pyo" -delete 2>/dev/null || true

  cd ${TMP_PKG_PATH}
  echo "Current directory: $(pwd)"
  ls -la
  tar -zcf "${pkg_name}" ${pkg_dir_name}
  rm -rf ${TMP_PKG_PATH}/${pkg_dir_name}
  rm -rf ${pkg_dir_name}
  echo "Packing ${pkg_name} success"

  # Unified symbols package: includes DSS symbols + database/CM/other component symbols
  if [[ ${DSSENABLED} == "TRUE" ]] || [ -d "${OGDB_CODE_PATH}/output/symbol" ]; then
    local sym_pkg_name="${BUILD_PACK_NAME}-${ograc_version}"
    if [[ -n "${os_distro_part}" ]]; then
      sym_pkg_name="${sym_pkg_name}-${os_distro_part}"
    fi
    if [[ ${BUILD_MODE} == "single" ]]; then
      sym_pkg_name="${sym_pkg_name}-${BUILD_MODE}"
    fi
    sym_pkg_name="${sym_pkg_name}${build_type_suffix}-${ENV_TYPE}-symbols.tgz"
    echo "Start packing symbols ${sym_pkg_name}..."

    mkdir -p ${TMP_PKG_PATH}/${pkg_dir_name}_symbols
    # Collect DSS symbols
    if [[ ${DSSENABLED} == "TRUE" ]] && [ -d "${OGDB_CODE_PATH}/dss_symbols" ]; then
      cp -arf "${OGDB_CODE_PATH}"/dss_symbols/* ${TMP_PKG_PATH}/${pkg_dir_name}_symbols/
    fi
    # Collect oGRAC database/CM/other component symbols
    if [ -d "${OGDB_CODE_PATH}/output/symbol" ]; then
      mkdir -p ${TMP_PKG_PATH}/${pkg_dir_name}_symbols/ograc
      cp -arf "${OGDB_CODE_PATH}"/output/symbol/* ${TMP_PKG_PATH}/${pkg_dir_name}_symbols/ograc/
    fi

    cd ${TMP_PKG_PATH}/${pkg_dir_name}_symbols
    tar -zcf "${TMP_PKG_PATH}/${sym_pkg_name}" .
    cd - > /dev/null
    rm -rf ${TMP_PKG_PATH}/${pkg_dir_name}_symbols
    echo "Packing ${sym_pkg_name} success"
  fi
}

function prepare() {
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
    chmod 700 "${OGDB_TARGET_PATH}"
  fi
  cp -arf "${OGDB_CODE_PATH}"/oGRAC-DATABASE-LINUX-64bit "${OGDB_TARGET_PATH}"/
}

BUILD_TYPE=${1,,}
if [[ ${BUILD_TYPE} != "debug" ]] && [[ ${BUILD_TYPE} != "release" ]]; then
  echo "Usage: ${0##*/} {debug|release}."
  exit 0
fi


if [ $# -ge 2 ] && [ "$2" = "--with-dss" ]; then
  DSSENABLED="TRUE"
fi

OG_BUILD_TYPE="package-${BUILD_TYPE}"

prepare
buildCtOmPackage
packageTarget
if [[ ${DSSENABLED} == "TRUE" ]]; then
  buildDssPackage
fi
newPackageTarget
