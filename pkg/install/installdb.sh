#!/bin/bash
#
# This library is using the variables listed in cfg/cluster.ini, and value come from install.py#set_cluster_conf
#
source ~/.bashrc
running_mode=$(grep '"M_RUNING_MODE"' /opt/ograc/action/ograc/install_config.json | cut -d '"' -f 4)

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

  xtrace=$(set -o | awk '/xtrace/ {print($2)}')
  set -x
  i=0
  while ! ${success_cmd}; do
    echo -n "."
    sleep 1
    i=$((i + 1))
    if [ $i -eq ${attempts} ]; then
      break
    fi
  done
  echo
  if [ "$xtrace" == "on" ]; then set -x; fi
  ${success_cmd}
}

function log() {
  xtrace=$(set -o | awk '/xtrace/ {print($2)}')
  set +x
  echo -e $1 >> ${REPORT_FILE}
  echo -e $1
  if [ "$xtrace" == "on" ]; then set -x; fi
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
  wait_for_success 1800 is_db1_online_by_cms
  wait_for_success 1800 is_db1_online_by_query
}

function wait_node0_online() {
  function is_db0_online_by_cms() {
    cms stat -res db | awk '{print $1, $3, $6}' | grep "0 ONLINE 1"
  }
  wait_for_success 5400 is_db0_online_by_cms
}

function start_ogracd() {
  log "================ start ogracd ${NODE_ID} ================"

  if [ "${NODE_ID}" != 0 ]; then
    wait_node0_online || err "timeout waiting for node0"
    sleep 60
  fi

  echo "Start ogracd with mode=${START_MODE}, OGDB_HOME=${OGDB_HOME}, RUN_MODE=${RUN_MODE}"

  nohup ${OGDB_HOME}/bin/ogracd ${START_MODE} -D ${OGDB_DATA} >> ${STATUS_LOG} 2>&1 &
  
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

function start_cms() {
  log "=========== start cms ${NODE_ID} ================"
  if [ ${NODE_ID} == 0 ]; then
    if [ ${CLUSTER_SIZE} == 1 ]; then
      cms node -add 0 node0 127.0.0.1 ${CMS_PORT[0]}
    else
      for ((i = 0; i < ${CLUSTER_SIZE}; i++)); do
        cms node -add ${i} node${i} ${NODE_IP[$i]} ${CMS_PORT[$i]}
      done
    fi

    cms res -add db -type db -attr "script=${OGDB_HOME}/bin/cluster.sh"
  elif [ ${NODE_ID} == 1 ]; then
    wait_for_node1_in_cluster
  fi

  cms node -list
  cms res -list
  cms server -start >> ${STATUS_LOG} 2>&1 &
}

function prepare_cms_gcc() {
  if [ "${IS_RERUN}" == 1 ]; then
    return 0
  fi
  if [ "${NODE_ID}" == 0 ]; then
    log "zeroing ${GCC_HOME} on node ${NODE_ID}"
    dd if=/dev/zero of=${GCC_HOME} bs=1M count=1024
    cms gcc -reset -f
  fi
}

function install_ogracd() {
  start_ogracd
}

function install_cms() {
  prepare_cms_gcc
  start_cms
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
  
  if [[ "${PROCESS^^}" == "OGRACD" && "${RUN_MODE,,}" != "ogracd" && "${RUN_MODE,,}" != "ogracd_in_cluster" ]]; then
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

function check_ogracd_status() {
  num=`pidof ogracd | wc -l`
  if [ $num -gt 0 ];then
    echo "ogracd is running."
    return 1
  fi

  return 0
}

start_dss() {
    num=`ps -ef | grep -w dssserver | grep -v grep | grep -v defunct | wc -l`
    if [ $num -gt 0 ];then
        echo "dss is still running."
        dsscmd reghl -D $DSS_HOME
        if [ $? != 0 ]; then 
            err "failed to reghl by dss"
            exit 1
        fi
        return 0
    fi

    cms res -start dss -node "${NODE_ID}"
    if [ $? != 0 ]; then 
        err "failed to start dss"
        exit 1
    fi
    echo "start dss success."
    return 0
}

function temp_start_ogracd() {
  if [[ ${USE_GSS} == "True" ]]; then
      start_dss
  fi
  nohup ${OGDB_HOME}/bin/ogracd nomount -D ${OGDB_DATA} >> ${STATUS_LOG} 2>&1 &
  sleep 3
  num=`ps -ef | grep -w ogracd | grep -v grep | grep -v defunct | wc -l`
  if [ $num -gt 0 ];then
      echo "ogracd start success."
      return 0
  fi
  return 1
}

function stop_ogracd() {
  node_id=$(cat ${CMS_HOME}/cfg/cms.ini  | grep NODE_ID | awk '{print $3}')
  cms res -stop db -node $node_id -f
  set +e
  pid=`pidof ogracd`
  if [[ ! -z ${pid} ]]; then
    kill -35 $pid
    sleep 3
  fi

  num=`pidof ogracd | wc -l`
  if [[ $num -gt 0 ]];then
    log "ogracd is still running, failed to stop ograc."
    set -e
    return 1
  fi

  set -e
  return 0
}

function try_conn_ogsql() {
  local attempts=$1
  local times=0
  check_ogsql_conn
  local result=$?
  while true
  do
    if [ $result -eq 0 ]; then
      times=$((times + 1))
      if [ $times -eq ${attempts} ]; then
        return 1
      else
        sleep 1
        check_ogsql_conn
        result=$?
      fi
    else
      break
    fi
  done

  return 0
}

function check_ogsql_conn() {
    num=`${OGDB_HOME}/bin/ogsql / as sysdba -q -c "SELECT NAME FROM DV_DATABASE" | grep -c "connected"`
    if [ $num -ge 1 ]; then
      return 1
    else
      return 0
    fi
}

function main() {
  check_env
  parse_parameter "$@"
  
  set -e -u -x
  TMPCFG=$(mktemp /tmp/tmpcfg.XXXXXXX) || exit 1
  echo "create temp cfg file ${TMPCFG}"
  (cat ${CLUSTER_CONFIG} | sed 's/ *= */=/g') > $TMPCFG
  source $TMPCFG

  case ${PROCESS} in
  cms | CMS)
    log "================ Install cms process ================"
    install_cms
    ;;
  ogracd | OGRACD)
    log "================ Install ogracd process ================"
    install_ogracd
    ;;
  checkogracdstatus | CHECKOGRACDSTATUS)
    log "================ Check ogracd status before recovery ================"
    check_ogracd_status
    return $?
    ;;
  tempstartogracd | TEMPSTARTOGRACD)
    log "================ Start ogracd temporary for recovery ================"
    temp_start_ogracd
    return $?
    ;;
  stopogracd | STOPOGRACD)
    log "================ Stop ogracd after recovery ================"
    stop_ogracd
    return $?
    ;;
  tryconnogsql | TRYCONNOGSQL)
    log "================ try conn ogsql for recovery ================"
    set +e
    try_conn_ogsql 300
    set -e
    return $?
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
