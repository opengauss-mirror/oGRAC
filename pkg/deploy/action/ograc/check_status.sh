# 确定相对路径
set +x
#当前路径
CURRENT_PATH=$(dirname $(readlink -f $0))
OGRAC_CHECK_STATUS_PY_NAME="ograc_check_status.py"

OGRAC_INSTALL_LOG_FILE=/opt/ograc/log/ograc/ograc_deploy.log
# 判断是否存在对应的文件，不存在返回报错，存在则继续运行
function check_ograc_status()
{
    user=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_user"`
    if [ ! -f  ${CURRENT_PATH}/${OGRAC_CHECK_STATUS_PY_NAME} ]; then
        echo "${OGRAC_CHECK_STATUS_PY_NAME} is not exist.]" >> ${OGRAC_INSTALL_LOG_FILE}
        return 1
    fi

    python3 ${CURRENT_PATH}/ograc_check_status.py

    if [ $? -ne 0 ]; then
        echo "Instance ogracd has not started." >> ${OGRAC_INSTALL_LOG_FILE}
        return 1
    fi

    echo "Instance ogracd has been started." >> ${OGRAC_INSTALL_LOG_FILE}
    return 0
}

check_ograc_status