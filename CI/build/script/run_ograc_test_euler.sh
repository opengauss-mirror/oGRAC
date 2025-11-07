#!/bin/bash
set -x
DIR_PATH=$(cd `dirname $0`;pwd)
CURRENT_CODE_PATH=$(cd ${DIR_PATH}/../../../;pwd)
if [ "${WORKSPACE}" != "" ]; then
  ln -s ${WORKSPACE}/ograc/ /home/regress
  sed -i 's/ogracKernel/ograc/g' ${CURRENT_CODE_PATH}/CI/CMC/ogracKernel_opensource_dependency.xml
fi
OGDB_CODE_PATH="/home/jenkins/agent/workspace/multiarch/openeuler/aarch64/ograc/oGRAC"
USER="jenkins"

function init_container() {
  echo "start init container"
  oGRAC_data_path="/home/jenkins/agent/workspace/multiarch/openeuler/aarch64/ograc/ograc_data"
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
    part1)            script_path="${CURRENT_CODE_PATH}/CI/script/Dev_euler_ograc_regress.sh"; og_schedule_list="og_schedule_part1"   ;;
    og_regress)       script_path="${CURRENT_CODE_PATH}/CI/script/Dev_euler_ograc_regress.sh"; og_schedule_list="og_schedule"   ;;
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
