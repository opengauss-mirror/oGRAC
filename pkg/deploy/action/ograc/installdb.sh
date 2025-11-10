#!/bin/bash
#
# This library is using the variables listed in cfg/cluster.ini, and value come from install.py#set_cluster_conf
#

CURRENT_PATH=$(dirname $(readlink -f $0))

function help() {
    echo ""
    echo "$1"
    echo ""
    echo "Usage: installdb.sh -P CMS|GSS|OGRACD -M NOMOUNT|OPEN|MOUNT -T ... [-R]"
    echo "          -P    start process: CMS, GSS, OGRACD"
    echo "          -M    start mode: NOMOUNT, OPEN, MOUNT"
    echo "          -R    if it's restart"
    echo "          -T    run type:ogracd, ogracd_in_cluster"
}

function clean() {
  if [[ -e ${TMPCFG} ]]; then
    rm -f ${TMPCFG}
    log "remove temp config file ${TMPCFG}"
  fi
}

trap clean EXIT

function wait_for_success() {
  local attempts=$1
  local success_cmd=${@:2}

  i=0
  while ! ${success_cmd}; do
    echo -n "."
    sleep 1
    i=$((i + 1))
    if [ $i -eq ${attempts} ]; then
      break
    fi
  done
}

function log() {
  printf "[%s] %s\n" "`date -d today \"+%Y-%m-%d %H:%M:%S\"`" "$1"
}

function err() {
  log "$@"
  exit 2
}

function wait_node1_online() {

  function is_db1_online_by_cms() {
    cms stat -res db | grep -E "^1[[:blank:]]+db[[:blank:]]+ONLINE"
  }

  function is_db1_online_by_query() {
    ${OGDB_HOME}/bin/ogsql / as sysdba -q -c "SELECT NAME, STATUS, OPEN_STATUS FROM DV_DATABASE"
  }
  log "query db1 by cms, please wait..."
  wait_for_success 1800 is_db1_online_by_cms
  log "query db1 by ogsql, please wait..."
  wait_for_success 1800 is_db1_online_by_query
}

function wait_node0_online() {
  function is_db0_online_by_cms() {
    cms stat -res db | awk '{print $1, $3, $6}' | grep "0 ONLINE 1"
  }
  wait_for_success 5400 is_db0_online_by_cms
}

function dss_reghl() {
  log "start register node ${NODE_ID} by dss"
  dsscmd reghl -D ${DSS_HOME} >> /dev/null 2>&1
  if [ $? != 0 ]; then err "failed to register node ${NODE_ID} by dss"; fi
}

function start_ogracd() {
  log "================ start ogracd ${NODE_ID} ================"
  ever_started=`python3 ${CURRENT_PATH}/get_config_info.py "OGRAC_EVER_START"`
  deploy_mode=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_mode"`
  numactl_str=" "
  set +e
  numactl --hardware
  if [ $? -eq 0 ]; then
    OS_ARCH=$(uname -i)
    if [[ ${OS_ARCH} =~ "aarch64" ]] && [[ ${deploy_mode} != "dss" ]]; then
      result_str=`python3 ${CURRENT_PATH}/get_config_info.py "OGRAC_NUMA_CPU_INFO"`
      if [ -z "$result_str" ]; then
          echo "Error: OGRAC_NUMA_CPU_INFO is empty."
          exit 1
      fi
      numactl_str="numactl -C ${result_str} "
    fi
  fi
  set -e
  if [ "${NODE_ID}" != 0 ] && [ "${ever_started}" != "True" ]; then
    wait_node0_online || err "timeout waiting for node0"
    sleep 60
  fi

  log "Start ogracd with mode=${START_MODE}, OGDB_HOME=${OGDB_HOME}, RUN_MODE=${RUN_MODE}"
  if [ ${deploy_mode} == "dss" ]; then
    dss_reghl
  fi

  # 如果ograc被cms抢占拉起，等待此ograc拉起完成，并跳过安装部署的启动ograc进程命令
  ogracd_pid=$(ps -ef | grep -v grep | grep ogracd | grep -w 'ogracd -D /mnt/dbdata/local/ograc/tmp/data' | awk '{print $2}')
  if [ ! -z "${ogracd_pid}" ]; then
    log "cms has start ogracd already"
    if [ "${NODE_ID}" == 0 ]; then
      wait_node0_online || err "timeout waiting for node0"
    else
      wait_node1_online || err "timeout waiting for node1"
    fi
    echo "instance started" >> /mnt/dbdata/local/ograc/tmp/data/log/ogracstatus.log
    return 0
  fi
  if [ "${ever_started}" == "True" ]; then
    cms res -start db -node "${NODE_ID}"
    if [ $? -eq 0 ]; then
      echo "instance started" >> /mnt/dbdata/local/ograc/tmp/data/log/ogracstatus.log
    else
      echo "instance startup failed" >> /mnt/dbdata/local/ograc/tmp/data/log/ogracstatus.log
    fi
  else
    nohup ${numactl_str} ${OGDB_HOME}/bin/ogracd ${START_MODE} -D ${OGDB_DATA} >> ${STATUS_LOG} 2>&1 &
  fi
  
  if [ $? != 0 ]; then err "failed to start ogracd"; fi

  if [ "${NODE_ID}" == 1 ]; then
    wait_node1_online || err "timeout waiting for node1"
  fi
}

function wait_for_node1_in_cluster() {
  function is_node1_joined_cluster() {
    cms node -list | grep -q node1
  }
  wait_for_success 60 is_node1_joined_cluster
}

function install_ogracd() {
  start_ogracd
}

function parse_parameter() {
  ARGS=$(getopt -o RSP:M:T:C: -n 'installdb.sh' -- "$@")
  
  if [ $? != 0 ]; then
    log "Terminating..."
    exit 1
  fi

  eval set -- "${ARGS}"
  
  declare -g PROCESS=
  declare -g START_MODE=
  declare -g IS_RERUN=0
  declare -g RUN_MODE=
  declare -g CLUSTER_CONFIG="${OGDB_DATA}/cfg/cluster.ini"
  declare -g SINGLE_FLAG="/opt/ograc/ograc/cfg/single_flag"
  
  while true
  do
    case "$1" in
      -P)
        PROCESS="$2"
        shift 2
        ;;
      -M)
        START_MODE="$2"
        shift 2
        ;;
      -T)
        RUN_MODE="$2"
        shift 2
        ;;
      -R)
        IS_RERUN=1
        shift
        ;;
      --)
        shift
        break
        ;;
      *)
        help "Internal error!"
        exit 1
        ;;
    esac
  done

  if [[ "${PROCESS^^}" == "OGRACD" && "${START_MODE^^}" != "NOMOUNT" && "${START_MODE^^}" != "OPEN" && "${START_MODE^^}" != "MOUNT" ]]; then
    help "Wrong start mode ${START_MODE} for ogracd passed by -M!"
    exit 1
  fi
  
  if [[ "${PROCESS^^}" == "OGRACD" && "${RUN_MODE}" != "ogracd" &&"${RUN_MODE}" != "ogracd_in_cluster" ]]; then
    help "Wrong run mode ${RUN_MODE} for ogracd passed by -T!"
    exit 1
  fi
  
  if [ ! -f "${CLUSTER_CONFIG}" ]; then
    help "Cluster config file ${CLUSTER_CONFIG} passed by -F not exists!"
    exit 1
  fi
}

function check_env() {
    if [ -z $OGDB_HOME ]; then
        err "Environment Variable OGDB_HOME NOT EXISTS!"
        exit 1
    fi

    if [ -z $OGDB_DATA ]; then
        err "Environment Variable OGDB_DATA NOT EXISTS!"
        exit 1
    fi
}

function main() {
  source ~/.bashrc
  check_env
  parse_parameter "$@"
  
  set -e -u
  TMPCFG=$(mktemp /tmp/tmpcfg.XXXXXXX) || exit 1
  log "create temp cfg file ${TMPCFG}"
  (cat ${CLUSTER_CONFIG} | sed 's/ *= */=/g') > $TMPCFG
  source $TMPCFG

  case ${PROCESS} in
  ogracd | OGRACD)
    log "================ Install ogracd process ================"
    install_ogracd
    ;;
  *)
    help "Wrong start process passed by -P!"
    exit 1
    ;;
  esac
  
  log "${PROCESS} processed ok !!"
  exit 0
}

main "$@"
