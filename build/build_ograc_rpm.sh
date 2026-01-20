#!/bin/bash
set -e
CURRENT_PATH=$(dirname $(readlink -f $0))
source "${CURRENT_PATH}"/common.sh
OGDB_CODE_PATH="${CURRENT_PATH}"/..
BUILD_PACK_NAME="openGauss_oGRAC"
ENV_TYPE=$(uname -p)
BUILD_TYPE="release"

function buildDssPackage() {
  sh "${CURRENT_PATH}"/build_dss.sh ${BUILD_TYPE}
}

function buildOGRACPackage() {
  echo "compiling oGRAC"
  sh "${CURRENT_PATH}"/Makefile.sh "${OG_BUILD_TYPE}"
}

function buildRPM() {
    echo "Prepare path for tar of source"

    echo "Get run dir name"
    cd ${OGRACDB_OUTPUT}/bin/oGRAC-RUN*
    if [ $? -ne 0 ]; then
        echo "too many oGRAC-RUN dir or dir not found"
        return 1
    fi

    local OGRAC_RUN_DIR=`pwd`
    cd ${CURRENT_PATH}
    local RPMALL_TOP_DIR="${OGRACDB_OUTPUT}/rpm"

    if [ -d ${RPMALL_TOP_DIR} ]; then
        rm -rf ${RPMALL_TOP_DIR}
    fi

    mkdir -p ${RPMALL_TOP_DIR}/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
    mkdir -p ${RPMALL_TOP_DIR}/SOURCES/{cms,dss,ograc,og_om,log}
    local ROOT_RPMTAR_PATH="${RPMALL_TOP_DIR}/SOURCES"
    echo "Prepare common"
    cp -arf "${OGDB_CODE_PATH}"/pkg/deploy/action ${ROOT_RPMTAR_PATH}
    cp -arf "${OGDB_CODE_PATH}"/pkg/deploy/config ${ROOT_RPMTAR_PATH}
    cp -arf "${OGDB_CODE_PATH}"/common ${ROOT_RPMTAR_PATH}
    cp -arf "${CURRENT_PATH}"/versions.yml ${ROOT_RPMTAR_PATH}/
    sed -i "/main \$@/i CSTOOL_TYPE=${BUILD_TYPE}" ${ROOT_RPMTAR_PATH}/action/dbstor/check_usr_pwd.sh
    sed -i "/main \$@/i CSTOOL_TYPE=${BUILD_TYPE}" ${ROOT_RPMTAR_PATH}/action/dbstor/check_dbstor_compat.sh
    sed -i "/main \$@/i CSTOOL_TYPE=${BUILD_TYPE}" ${ROOT_RPMTAR_PATH}/action/inspection/inspection_scripts/kernal/check_link_cnt.sh

    echo "Prepare cms"
    mkdir -p ${ROOT_RPMTAR_PATH}/cms/service
    cp -arf "${OGRAC_RUN_DIR}"/add-ons ${ROOT_RPMTAR_PATH}/cms/service
    cp -arf "${OGRAC_RUN_DIR}"/admin ${ROOT_RPMTAR_PATH}/cms/service
    cp -arf "${OGRAC_RUN_DIR}"/bin ${ROOT_RPMTAR_PATH}/cms/service
    cp -arf "${OGRAC_RUN_DIR}"/cfg ${ROOT_RPMTAR_PATH}/cms/service
    cp -arf "${OGRAC_RUN_DIR}"/lib ${ROOT_RPMTAR_PATH}/cms/service
    cp -arf "${OGRAC_RUN_DIR}"/package.xml ${ROOT_RPMTAR_PATH}/cms/service
    echo "Prepare og_om"
    cp -arf "${OGDB_CODE_PATH}"/og_om/. ${ROOT_RPMTAR_PATH}/og_om
    echo "Prepare dss"
    cp -arf ${OGDB_CODE_PATH}/CBB/output/bin "${ROOT_RPMTAR_PATH}"/dss
    cp -arf ${OGDB_CODE_PATH}/CBB/output/lib "${ROOT_RPMTAR_PATH}"/dss
    cp -arf ${OGDB_CODE_PATH}/DSS/output/bin "${ROOT_RPMTAR_PATH}"/dss
    cp -arf ${OGDB_CODE_PATH}/DSS/output/lib "${ROOT_RPMTAR_PATH}"/dss
    echo "Prepare ograc"
    mkdir -p ${ROOT_RPMTAR_PATH}/ograc/server
    cp -rf ${OGRAC_RUN_DIR}/add-ons ${ROOT_RPMTAR_PATH}/ograc/server/
    cp -rf ${OGRAC_RUN_DIR}/bin ${ROOT_RPMTAR_PATH}/ograc/server/
    rm -rf ${ROOT_RPMTAR_PATH}/ograc/server/bin/cms
    cp -rf ${OGRAC_RUN_DIR}/lib ${ROOT_RPMTAR_PATH}/ograc/server/
    cp -rf ${OGRAC_RUN_DIR}/admin ${ROOT_RPMTAR_PATH}/ograc/server/
    cp -rf ${OGRAC_RUN_DIR}/cfg ${ROOT_RPMTAR_PATH}/ograc/server/
    cp -rf ${OGRAC_RUN_DIR}/package.xml ${ROOT_RPMTAR_PATH}/ograc/server/
    touch ${ROOT_RPMTAR_PATH}/installed_by_rpm
    echo "1" > ${ROOT_RPMTAR_PATH}/installed_by_rpm
    echo "Generate tar"
    bash "${CURRENT_PATH}"/rpm_build_allinone.sh
}

OG_BUILD_TYPE="package-${BUILD_TYPE}"

buildOGRACPackage
buildDssPackage
buildRPM
