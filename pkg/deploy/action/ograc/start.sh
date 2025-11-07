# 确定相对路径
set +x
#当前路径
CURRENT_PATH=$(dirname $(readlink -f $0))
OGRAC_START_PY_NAME="ograc_start.py"
OGRAC_STOP_SH_NAME="stop.sh"
OGRAC_INSTALL_LOG_FILE=/opt/ograc/log/ograc/ograc_deploy.log
START_MODE=$1

function log() {
  printf "[%s] %s\n" "`date -d today \"+%Y-%m-%d %H:%M:%S\"`" "$1" >> ${OGRAC_INSTALL_LOG_FILE}
}

function check_ograc_exporter_daemon_status()
{
    for i in {1..3}
    do
        sleep 1
        ogracd_pid=$(ps -ef | grep ogracd | grep -v grep | awk 'NR==1 {print $2}')
    done
    # ce_pid不存在
    if [ -z "${ogracd_pid}" ];then
        return 1
    fi
    log "ogracd process has exist."
    return 0
} 

# 判断是否存在对应的文件，不存在返回报错，存在则继续运行
function ograc_start()
{
    if [ ! -f  ${CURRENT_PATH}/${OGRAC_START_PY_NAME} ]; then
        log "${OGRAC_START_PY_NAME} is not exist.]"
        return 1
    fi
    # 容灾备站点拉起时，无需创库。设置创库状态为done
    if [[ x"${START_MODE}" == x"standby" ]];then
        sed -i 's/"db_create_status": "default"/"db_create_status": "done"/g'  /opt/ograc/ograc/cfg/start_status.json
    fi
    export LD_LIBRARY_PATH=/opt/ograc/dbstor/lib:${LD_LIBRARY_PATH}
    python3 ${CURRENT_PATH}/${OGRAC_START_PY_NAME}
    ret=$?

    if [ ${ret} -ne 0 ]; then
        log "Execute ${OGRAC_START_PY_NAME} return ${ret}."
        return 1
    fi

    log "ograc start success."
    return 0
}

# 读取ograc创库流程状态，如果ograc在创库流程被中断，则需要卸载后修改namespace并重新安装
function check_ograc_db_create_status()
{
    OGRAC_SQL_EXECUTE_STATUS=`python3 ${CURRENT_PATH}/get_config_info.py "OGRAC_DB_CREATE_STATUS"`

    if [ -z ${OGRAC_SQL_EXECUTE_STATUS} ]; then
        log "Failed to get db create status, please check file start_status.json or reinstall ograc."
        exit 1
    fi

    if [ ${OGRAC_SQL_EXECUTE_STATUS} == "creating" ]; then
        log "Failed to create namespace at last startup, please reinstall it after uninstalling ograc and modifying namespace."
        exit 1
    fi
}

function check_ograc_start_status()
{
    OGRAC_START_STATUS=`python3 ${CURRENT_PATH}/get_config_info.py "OGRAC_START_STATUS"`

    # 1.ograc拉起状态为starting，即ograc拉起过程中异常退出了。此时，若ograc进程不存在，stop后重新拉起ograc
    # 在database的创建流程之外ograc被异常退出时，ograc还可以再次被拉起
    ret=check_ograc_exporter_daemon_status
    if [[ ${OGRAC_START_STATUS} == "starting" && ${ret} -ne 0 ]]; then
        log "Last startup process was interrupted, trying to stop existing ograc process and restart it."
        sh ${CURRENT_PATH}/${OGRAC_STOP_SH_NAME}
    fi

    # 2.ograc拉起状态为started
    #（2.1）ograc进程在，直接返回0（成功）
    #（2.2）ograc进程不在，先强制stop，再重新拉起ograc
    if [ ${OGRAC_START_STATUS} == "started" ]; then
        check_ograc_exporter_daemon_status
        if [ $? -eq 0 ]; then
            log "ograc is already started, no need to restart it."
            exit 0
        else
            log "ograc status is started, but no process is detected, trying to restart it."
            sh ${CURRENT_PATH}/${OGRAC_STOP_SH_NAME}
        fi
    fi
}

check_ograc_db_create_status
check_ograc_start_status
ograc_start