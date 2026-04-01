# 确定相对路径
set +x
#当前路径
CURRENT_PATH=$(dirname $(readlink -f $0))
OGRAC_INSTALL_PY_NAME="ograc_install.py"
RPM_UNPACK_PATH="/opt/ograc/image/oGRAC-RUN-LINUX-64bit"

OGRAC_INSTALL_LOG_FILE=/opt/ograc/log/ograc/ograc_deploy.log
OGRAC_INSTALL_CONFIG=/opt/ograc/ograc/cfg

function log() {
  printf "[%s] %s\n" "`date -d today \"+%Y-%m-%d %H:%M:%S\"`" "$1" >> ${OGRAC_INSTALL_LOG_FILE}
}

# 判断是否存在对应的文件，不存在返回报错，存在则继续运行
function ograc_install()
{

    install_type=$(python3 ${CURRENT_PATH}/get_config_info.py "install_type")
    node_id=$(python3 ${CURRENT_PATH}/get_config_info.py "node_id")
    ograc_use=$(python3 ${CURRENT_PATH}/get_config_info.py "deploy_user")
    ograc_group=$(python3 ${CURRENT_PATH}/get_config_info.py "deploy_group")
    mes_ssl_switch=$(python3 ${CURRENT_PATH}/get_config_info.py "mes_ssl_switch")
    deploy_mode=$(python3 ${CURRENT_PATH}/get_config_info.py "deploy_mode")
    cert_encrypt_pwd=""
    user_pwd=""

    if [[ ${install_type} = "override" ]]; then
        is_encrept=0
        read -s -p "Please Input SYS_PassWord: " user_pwd
        if [[ ${mes_ssl_switch} == "True" ]];then
            read -s -p "Please Input cert passwd: " cert_encrypt_pwd
        fi
    else
        is_encrept=1
        SYS_PASSWORD=`python3 ${CURRENT_PATH}/get_config_info.py "SYS_PASSWORD"`
        if [[ ${SYS_PASSWORD} != "" ]]; then
            user_is_encrept=${SYS_PASSWORD}
        else
            log "SYS_PASSWORD NOT FOUND"
            return 1
        fi
    fi

    if [ ! -f  ${CURRENT_PATH}/${OGRAC_INSTALL_PY_NAME} ]; then
        log " ${OGRAC_INSTALL_PY_NAME} is not exist."
        return 1
    fi

    if [ -d /mnt/dbdata/local/ograc/tmp/data ]; then
        rm -rf /mnt/dbdata/local/ograc/tmp/data
    fi

    if [ ! -d /opt/ograc/ograc/server ]; then
        mkdir -p -m 750 /opt/ograc/ograc/server
    fi

    if [ ! -d /mnt/dbdata/local/ograc/tmp/data ]; then
        mkdir -p -m 750 /mnt/dbdata/local/ograc/tmp/data
    fi
    chmod 750 /mnt/dbdata/local/ograc/tmp

    if [ ! -d /opt/ograc/log/ograc ]; then
        mkdir -p -m 750 /opt/ograc/log/ograc
    fi

    if [ ! -f /opt/ograc/installed_by_rpm ]; then
        cp -rf ${RPM_UNPACK_PATH}/add-ons /opt/ograc/ograc/server/
        cp -rf ${RPM_UNPACK_PATH}/bin /opt/ograc/ograc/server/
        rm -rf /opt/ograc/ograc/server/bin/cms
        cp -rf ${RPM_UNPACK_PATH}/lib /opt/ograc/ograc/server/
        cp -rf ${RPM_UNPACK_PATH}/admin /opt/ograc/ograc/server/
        cp -rf ${RPM_UNPACK_PATH}/cfg /opt/ograc/ograc/server/
        cp -rf ${RPM_UNPACK_PATH}/package.xml /opt/ograc/ograc/server/
        log "rpm files copy success."
    fi
    chmod 700 -R /opt/ograc/ograc/server
    # 执行主文件
    cd ${CURRENT_PATH}
    if [ ${is_encrept} -eq 0 ]; then
        source ~/.bashrc
        export LD_LIBRARY_PATH=/opt/ograc/dbstor/lib:${LD_LIBRARY_PATH}
        echo -e "${user_pwd}\n${cert_encrypt_pwd}" | python3 ${CURRENT_PATH}/ograc_install.py -s password
        ret=$?
        if [ $ret -ne 0 ]; then
            log "Execute ${OGRAC_INSTALL_PY_NAME} return $ret."
            return 1
        fi
    else
        cp -r /opt/ograc/backup/files/ograc/dbstor_config.ini /mnt/dbdata/local/ograc/tmp/data/dbstor/conf/dbs/
        cp -f /opt/ograc/backup/files/ograc/ogracd.ini /mnt/dbdata/local/ograc/tmp/data/cfg/
        cp -f /opt/ograc/backup/files/ograc/ogsql.ini /mnt/dbdata/local/ograc/tmp/data/cfg/
        cp -f /opt/ograc/backup/files/ograc/ograc_config.json ${OGRAC_INSTALL_CONFIG}/
        echo -e "${user_is_encrept}\n${cert_encrypt_pwd}" | python3 ${CURRENT_PATH}/ograc_install.py -s password -t reserve
        ret=$?
        if [ $ret -ne 0 ]; then
            log "Execute ${OGRAC_INSTALL_PY_NAME} return $ret."
            return 1
        fi
    fi

    if [[ ${is_encrept} -eq 1 ]]; then
        rm -rf /mnt/dbdata/local/ograc/tmp/data/dbstor/conf/dbs/dbstor_config.ini
        cp -r /opt/ograc/backup/files/ograc/dbstor_config.ini /mnt/dbdata/local/ograc/tmp/data/dbstor/conf/dbs/
        rm -rf /mnt/dbdata/local/ograc/tmp/data/cfg
        cp -rf /opt/ograc/backup/files/ograc/cfg /mnt/dbdata/local/ograc/tmp/data/
        rm -rf ${CURRENT_PATH}/ograc_config.json
        cp -f /opt/ograc/backup/files/ograc/ograc_config.json ${CURRENT_PATH}/
    fi

    log "ograc install success."

    return 0
}

ograc_install