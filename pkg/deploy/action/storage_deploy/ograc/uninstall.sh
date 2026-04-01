# 确定相对路径
set +x
#当前路径
CURRENT_PATH=$(dirname $(readlink -f $0))
OGRAC_UNINSTALL_PY_NAME="ograc_uninstall.py"
OGRAC_INSTALL_LOG_FILE=/opt/ograc/log/ograc/ograc_deploy.log

function log() {
  printf "[%s] %s\n" "`date -d today \"+%Y-%m-%d %H:%M:%S\"`" "$1"
}

# 判断是否存在对应的文件，不存在返回报错，存在则继续运行
function ograc_uninstall()
{
    log "shell uninstall step 0 $(date)"
    log "shell uninstall step 1 $(date)"
    ograc_user=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_user"`
    log "shell uninstall step 2 $(date)"
    ograc_data=$(cat ${CURRENT_PATH}/install_config.json |
              awk -F ',' '{for(i=1;i<=NF;i++){if($i~"D_DATA_PATH"){print $i}}}' |
              sed 's/ //g' | sed 's/:/=/1' | sed 's/"//g' |
              awk -F '=' '{print $2}')
    ograc_count=`ps -fu ${ograc_user} | grep "\-D ${ograc_data}" | grep -vE '(grep|defunct)' | wc -l`
    if [ ${ograc_count} -ge 1 ];then
        log "Error: ograc process is running, please stop before uninstall"
        return 1
    fi
    log "shell uninstall step 3 $(date)"
    if [ ! -f  ${CURRENT_PATH}/${OGRAC_UNINSTALL_PY_NAME} ]; then
        echo "${OGRAC_UNINSTALL_PY_NAME} is not exist.]"
        return 1
    fi
    log "shell uninstall step 4 $(date)"
    storage_metadata_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_metadata_fs"`
    python3 ${CURRENT_PATH}/ograc_uninstall.py ${uninstall_type} ${force_uninstall}

    ret=$?
    if [ ${ret} -ne 0 ]; then
        log "Execute ${OGRAC_UNINSTALL_PY_NAME} return ${ret}."
        return 1
    fi

    log "shell uninstall step 5 $(date)"
    if [ -d /mnt/dbdata/local/ograc/tmp/data/log ]; then
        mkdir -p -m 750 /opt/ograc/log/ograc/ograc_start_log
        yes | cp -arf /mnt/dbdata/local/ograc/tmp/data/log /opt/ograc/log/ograc/ograc_start_log
    fi

    if [ $? -ne 0 ]; then
        log "Copy log file or dir failed, please check the permission and manually repair this."
        return 1
    fi

    log "shell uninstall step 6 $(date)"
    if [ -d /mnt/dbdata/local/ograc/tmp/data ]; then
        rm -rf /mnt/dbdata/local/ograc/tmp/data
    fi

    if [ $? -ne 0 ]; then
        log "Remove data file or dir failed, please check the permission and manually repair this."
        return 1
    fi

    log "shell uninstall step 7 $(date)"
    log "ograc uninstall success."

    return 0
}

uninstall_type=$1
force_uninstall=$2
ograc_uninstall &>> ${OGRAC_INSTALL_LOG_FILE}