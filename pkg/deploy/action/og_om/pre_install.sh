#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
OG_OM_PATH=/opt/ograc/action/og_om
OG_OM_LOG_PATH=/opt/ograc/log/og_om
OG_OM_OGMGR=/opt/ograc/og_om/service/ogmgr
ACTION_TYPE=$1

source ${CURRENT_PATH}/og_om_log.sh

LOG_MOD=740
OG_OM_DIR_MOD=700
OG_OM_FILE_MOD=400
OGMGR_USER_FILE_LIST=('check_status.sh' 'start.sh' 'stop.sh')

# 修改/opt/ograc/log/og_om/日志文件属性
if [ -d ${OG_OM_LOG_PATH} ]; then
    chmod -Rf ${LOG_MOD} ${OG_OM_LOG_PATH}
    if [ $? -eq 0 ]; then
        logAndEchoInfo "change mod of ${OG_OM_LOG_PATH} success"
    else
        logAndEchoError "change mod of ${OG_OM_LOG_PATH} failed"
        exit 1
    fi
fi

# 修改/opt/ograc/log/og_om/日志文件归属
if [ -d ${OG_OM_LOG_PATH} ]; then
    chmod 640 ${OG_OM_LOG_PATH}/om_deploy.log
    if [ $? -eq 0 ]; then
        logAndEchoInfo "change mod of ${OG_OM_LOG_PATH}/om_deploy.log success"
    else
        logAndEchoError "change mod of ${OG_OM_LOG_PATH}/om_deploy.log failed"
        exit 1
    fi

    chown -hR ogmgruser:ogmgruser ${OG_OM_LOG_PATH}
    if [ $? -eq 0 ]; then
        logAndEchoInfo "change owner of ${OG_OM_LOG_PATH} success"
    else
        logAndEchoError "change owner of ${OG_OM_LOG_PATH} failed"
        exit 1
    fi
fi

# 原子操作，仅将应为低权限属主的脚本改为低权限
for ogmgr_file in "${OGMGR_USER_FILE_LIST[@]}"; do
    chown -h ogmgruser:ogmgruser "${CURRENT_PATH}/${ogmgr_file}"
    if [ $? -eq 0 ]; then
        logAndEchoInfo "change owner of ${ogmgr_file} to ogmgruser success"
    else
        logAndEchoError "change owner of ${ogmgr_file} to ogmgruser failed"
        exit 1
    fi
done

# 仅安装部署和离线升级场景需要执行下方的拷贝操作
if [[ ${ACTION_TYPE} != "rollback" ]] && [[ ! -f /opt/ograc/installed_by_rpm ]];then
    # 把og_om代码拷贝到opt/ograc/action路径下
    cp -rpf ${CURRENT_PATH} /opt/ograc/action
    if [ $? -eq 0 ]; then
        logAndEchoInfo "copy og_om path to /opt/ograc/action success"
    else
        logAndEchoError "copy og_om path to /opt/ograc/action failed"
        exit 1
    fi
fi
