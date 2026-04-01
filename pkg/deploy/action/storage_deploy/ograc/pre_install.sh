# 确定相对路径
set +x
#当前路径
CURRENT_PATH=$(dirname $(readlink -f $0))

OGRAC_PRE_INSTALL_PY_NAME="ograc_pre_install.py"

function log() {
  printf "[%s] %s\n" "`date -d today \"+%Y-%m-%d %H:%M:%S\"`" "$1"
}

OGRAC_INSTALL_LOG_FILE=/opt/ograc/log/ograc/ograc_deploy.log

# 判断是否存在对应的文件，不存在返回报错，存在则继续运行
function ograc_pre_install()
{
    if [ ! -f  ${CURRENT_PATH}/${OGRAC_PRE_INSTALL_PY_NAME} ]; then
        echo " ${OGRAC_PRE_INSTALL_PY_NAME} is not exist.]"
        return 1
    fi

    if [ ! -d /opt/ograc/log/ograc ]; then
        mkdir -p -m 750 /opt/ograc/log/ograc
    fi

    python3 ${CURRENT_PATH}/ograc_pre_install.py

    if [ $? -ne 0 ]; then
        echo "Execute ${OGRAC_PRE_INSTALL_PY_NAME} return $?."
        return 1
    fi

    log "ograc pre install success."

    return 0
}

ograc_pre_install &>> ${OGRAC_INSTALL_LOG_FILE}