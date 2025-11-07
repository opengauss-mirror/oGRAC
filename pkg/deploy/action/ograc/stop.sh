# 确定相对路径
set +x
#当前路径
CURRENT_PATH=$(dirname $(readlink -f $0))
OGRAC_STOP_PY_NAME="ograc_stop.py"
OGRAC_STOP_CONFIG_NAME="ograc_uninstall_config.json"
OGRAC_CHECK_STATUS_PY_NAME="ograc_check_status.py"
OGRAC_START_STATUS=`python3 ${CURRENT_PATH}/get_config_info.py "OGRAC_START_STATUS"`
OGRAC_START_STATUS_FILE="/opt/ograc/ograc/cfg/start_status.json"
OGRAC_INSTALL_LOG_FILE=/opt/ograc/log/ograc/ograc_deploy.log

function log() {
  printf "[%s] %s\n" "`date -d today \"+%Y-%m-%d %H:%M:%S\"`" "$1"
}

# 判断是否存在对应的文件，不存在返回报错，存在则继续运行
function ograc_stop()
{
    user=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_user"`
    group=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_group"`
    if [ ! -f  ${CURRENT_PATH}/${OGRAC_CHECK_STATUS_PY_NAME} ]; then
        log "${OGRAC_CHECK_STATUS_PY_NAME} is not exist.]"
        return 1
    fi

    python3 ${CURRENT_PATH}/ograc_check_status.py

    if [ $? -ne 0 ] && [ x"${OGRAC_START_STATUS}" == x"default" ]; then
        log "ograc status is default, instance ogracd has not started."
        return 0
    fi

    if [ ! -f  ${CURRENT_PATH}/${OGRAC_STOP_PY_NAME} ]; then
        log "${OGRAC_STOP_PY_NAME} is not exist.]"
        return 1
    fi

    # # 进入user
    python3 ${CURRENT_PATH}/ograc_stop.py

    ret=$?
    if [ ${ret} -ne 0 ]; then
        log "Execute ${OGRAC_STOP_PY_NAME} return ${ret}."
        return 1
    fi
    log "ograc stop success."
    return 0
}

ograc_stop &>> ${OGRAC_INSTALL_LOG_FILE}
