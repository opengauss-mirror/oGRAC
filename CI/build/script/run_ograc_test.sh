#!/bin/bash
set -x
DIR_PATH=$(cd `dirname $0`;pwd)
CURRENT_CODE_PATH=$(cd ${DIR_PATH}/../../../;pwd)
if [ "${WORKSPACE}" != "" ]; then
  ln -s ${WORKSPACE}/ograc/ /home/regress
  sed -i 's/ogracKernel/ograc/g' ${CURRENT_CODE_PATH}/CI/CMC/ogracKernel_opensource_dependency.xml
fi
OGDB_CODE_PATH="/home/regress/ogracKernel"
USER="ogracdba"

function init_container() {
  echo "start init container"
  oGRAC_data_path="/home/regress/ograc_data"
  if [ ! -d $oGRAC_data_path ];then
    mkdir -p $oGRAC_data_path
  fi

  cat /etc/passwd | grep "${USER}" 
  if [ $? != 0 ]; then
    echo "${USER} is not exist, useradd ${USER}"
    rm -rf /home/${USER}
    useradd -m ${USER} -u 5000
  fi
  
  chown ${USER}:${USER} -R ${OGDB_CODE_PATH}/..
  rm -f /etc/maven/settings.xml
  cp ${CURRENT_CODE_PATH}/CI/maven/settings.xml /etc/maven/settings.xml
  echo "source /etc/profile" >> /root/.bashrc
  echo "alias ll='ls -alrt'" >> /etc/profile
  echo "ulimit -c unlimited" >> /root/.bashrc
  echo "/home/core/core-%e-%p-%t" > /proc/sys/kernel/core_pattern
  echo 2 > /proc/sys/fs/suid_dumpable
  source /root/.bashrc
  echo "init container success"
}

function run_test() {
  echo "Start run_test..."
  echo "OGDB_CODE_PATH: ${OGDB_CODE_PATH}"
  pram=$1
  case $pram in
    part1)            script_path="${CURRENT_CODE_PATH}/CI/script/Dev_ograc_regress.sh"; og_schedule_list="og_schedule_part1"   ;;
    part2)            script_path="${CURRENT_CODE_PATH}/CI/script/Dev_ograc_regress.sh"; og_schedule_list="og_schedule_part2"   ;;
    part3)            script_path="${CURRENT_CODE_PATH}/CI/script/Dev_ograc_regress.sh"; og_schedule_list="og_schedule_part3"   ;;
    part4)            script_path="${CURRENT_CODE_PATH}/CI/script/Dev_ograc_regress.sh"; og_schedule_list="og_schedule_part4"   ;;
    part5)            script_path="${CURRENT_CODE_PATH}/CI/script/Dev_ograc_regress.sh"; og_schedule_list="og_schedule_part5"   ;;
    part6)            script_path="${CURRENT_CODE_PATH}/CI/script/Dev_ograc_regress.sh"; og_schedule_list="og_schedule_part6"   ;;
    part7)            script_path="${CURRENT_CODE_PATH}/CI/script/Dev_ograc_regress.sh"; og_schedule_list="og_schedule_part7"   ;;
    part8)            script_path="${CURRENT_CODE_PATH}/CI/script/Dev_ograc_regress.sh"; og_schedule_list="og_schedule_part8"   ;;
    Dev_Basic)        script_path="${CURRENT_CODE_PATH}/CI/script/Dev_Basic_test.sh"; og_schedule_list="og_schedule"   ;;
    cms)              script_path="${CURRENT_CODE_PATH}/CI/script/Dev_cms_test.sh"; og_schedule_list="og_schedule"   ;;
    cms_ut)           script_path="${CURRENT_CODE_PATH}/CI/script/Dev_cms_unit_test.sh"; og_schedule_list="og_schedule"   ;;
    gtest)            script_path="${CURRENT_CODE_PATH}/CI/script/Dev_unit_test.sh"; og_schedule_list="og_schedule"   ;;
    cluster_part1)          script_path="${CURRENT_CODE_PATH}/CI/script/cluster_test.sh test_list_0"; og_schedule_list="og_schedule"   ;;
    cluster_part2)          script_path="${CURRENT_CODE_PATH}/CI/script/cluster_test.sh test_list_1"; og_schedule_list="og_schedule"   ;;
    Dev_unit_dtc)     script_path="${CURRENT_CODE_PATH}/CI/script/Dev_unit_dtc_test.sh"; og_schedule_list="og_schedule"   ;;
    cluster_ha_regress_1)           script_path="${CURRENT_CODE_PATH}/pkg/test/cluster_ha_regress/cluster_ha_regress.sh cluster_ha_regress11.lst"; og_schedule_list="og_schedule"   ;;
    cluster_ha_regress_2)           script_path="${CURRENT_CODE_PATH}/pkg/test/cluster_ha_regress/cluster_ha_regress.sh cluster_ha_regress12.lst"; og_schedule_list="og_schedule"   ;;
    cluster_ha_regress_3)           script_path="${CURRENT_CODE_PATH}/pkg/test/cluster_ha_regress/cluster_ha_regress.sh cluster_ha_regress13.lst"; og_schedule_list="og_schedule"   ;;
    cluster_ha_regress_4)           script_path="${CURRENT_CODE_PATH}/pkg/test/cluster_ha_regress/cluster_ha_regress.sh cluster_ha_regress14.lst"; og_schedule_list="og_schedule"   ;;
    cluster_ha_regress_5)           script_path="${CURRENT_CODE_PATH}/pkg/test/cluster_ha_regress/cluster_ha_regress.sh cluster_ha_regress15.lst"; og_schedule_list="og_schedule"   ;;
    Dev_mes_unit)     script_path="${CURRENT_CODE_PATH}/CI/script/Dev_mes_unit_test.sh"; og_schedule_list="og_schedule"   ;;
    Dev_all_unit)     script_path="${CURRENT_CODE_PATH}/CI/script/Dev_run_all_llt.sh"; og_schedule_list="og_schedule"   ;;
     *)
       echo "invalid pram ${pram}"
  esac
  echo "script_path is : ${script_path}"
  bash ${script_path} --coverage 1 --og_schedule_list ${og_schedule_list}
}

function change_shm_size() {
  echo "change_shm_size..."
  sudo mount -o size=10240M  -o remount /dev/shm
}

function linkCodeToHome() {
  # 如果代码路径不在HOME_PATH下，需要链接过去
  if [ -d ${OGDB_CODE_PATH} ]; then
      echo "code: ${OGDB_CODE_PATH} exist"
      return 0
  fi
  
  if [ -L ${OGDB_CODE_PATH} ]; then
    rm -f ${OGDB_CODE_PATH}
  fi

  local code_home=$(dirname $(realpath ${BASH_SOURCE[0]}))/../../../..
  ln -s ${code_home}/oGRAC ${OGDB_CODE_PATH}
  ln -s ${code_home}/oGRAC_om ${OGDB_CODE_PATH}/../oGRAC_om
  echo "link code to home success"
}

#installCert
linkCodeToHome
init_container
change_shm_size
run_test $@
