#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
OGRAC_EXPORTER_PATH=/opt/ograc/action/ograc_exporter
OGRAC_EXPORTER_LOG_PATH=/opt/ograc/log/ograc_exporter
OGRAC_EXPORTER_LOG_FILE=/opt/ograc/log/ograc_exporter/ograc_exporter.log
ACTION_TYPE=$1

source ${CURRENT_PATH}/../log4sh.sh
source ${CURRENT_PATH}/../env.sh

LOG_MOD=740
OGRAC_EXPORTER_DIR_MOD=755
OGRAC_EXPORTER_FILE_MOD=400
OGRACDBA_FILE_LIST=('ograc_exporter_log.sh' 'check_status.sh' 'start.sh' 'stop.sh')


# 原子操作，仅将应为低权限属主的脚本改为低权限
for ogracdba_file in "${OGRACDBA_FILE_LIST[@]}"; do
    chown -h "${ograc_user}":"${ograc_group}" "${CURRENT_PATH}/${ogracdba_file}"
    if [ $? -eq 0 ]; then
        logAndEchoInfo "change owner of ${ogracdba_file} to ograc success"
    else
        logAndEchoError "change owner of ${ogracdba_file} to ograc failed"
        exit 1
    fi
done

chmod ${OGRAC_EXPORTER_DIR_MOD} ${CURRENT_PATH}
chmod ${OGRAC_EXPORTER_FILE_MOD} ${CURRENT_PATH}/*

# 仅安装部署和离线升级场景需要执行下方的拷贝操作
if [[ ${ACTION_TYPE} != "rollback" ]];then
    # 把ograc_exporter代码拷贝到opt/ograc/action路径下
    cp -rpf ${CURRENT_PATH} /opt/ograc/action
    if [ $? -eq 0 ]; then
        logAndEchoInfo "copy ograc_exporter path to /opt/ograc/action success"
    else
        logAndEchoError "copy ograc_exporter path to /opt/ograc/action failed"
        exit 1
    fi
fi

# 修改/opt/ograc/og_om目录属组
if [ -d /opt/ograc/og_om ];then
    chown -h "${ograc_user}":"${ograc_common_group}" /opt/ograc/og_om
fi
if [ -d /opt/ograc/og_om/service ];then
    chown -h "${ograc_user}":"${ograc_common_group}" /opt/ograc/og_om/service
fi
if [ -d /opt/ograc/og_om/service/ograc_exporter ];then
    chown -hR "${ograc_user}":"${ograc_common_group}" /opt/ograc/og_om/service/ograc_exporter
fi

if [ ! -d ${OGRAC_EXPORTER_LOG_PATH} ]; then
    mkdir -m 750 -p ${OGRAC_EXPORTER_LOG_PATH}
    touch ${OGRAC_EXPORTER_LOG_FILE}
fi

if [ -d /opt/ograc/log/deploy/logs ];then
    chmod 755 /opt/ograc/log/deploy/logs
fi

if [ -d /opt/ograc/log/ograc_exporter ]; then
    # 修改/opt/ograc/log/ograc_exporter日志文件属性
    chmod -Rf ${LOG_MOD} /opt/ograc/log/ograc_exporter
    if [ $? -eq 0 ]; then
        logAndEchoInfo "change mod of /opt/ograc/log/ograc_exporter success"
    else
        logAndEchoError "change mod of /opt/ograc/log/ograc_exporter failed"
        exit 1
    fi
    # 修改/opt/ograc/log/ograc_exporter/ograc_exporter.log日志文件权限
    chmod 640 /opt/ograc/log/ograc_exporter/ograc_exporter.log
    if [ $? -eq 0 ]; then
        logAndEchoInfo "change mod of /opt/ograc/log/ograc_exporter/ograc_exporter.log success"
    else
        logAndEchoError "change mod of /opt/ograc/log/ograc_exporter/ograc_exporter.log failed"
        exit 1
    fi
    # 修改/opt/ograc/ograc_exporter 文件归属
    chown -hR "${ograc_user}":"${ograc_group}" /opt/ograc/log/ograc_exporter
    if [ $? -eq 0 ]; then
        logAndEchoInfo "change owner of /opt/ograc/log/ograc_exporter success"
    else
        logAndEchoError "change owner of /opt/ograc/log/ograc_exporter failed"
        exit 1
    fi
fi

if [ -d /opt/ograc/log/og_om ]; then
    chmod -Rf 640 /opt/ograc/log/og_om
    if [ $? -eq 0 ]; then
        logAndEchoInfo "recursively change mod of /opt/ograc/log/og_om"
    else
        logAndEchoError "recursively change mod of /opt/ograc/log/og_om"
        exit 1
    fi

    chmod -f 750 /opt/ograc/log/og_om
    if [ $? -eq 0 ]; then
        logAndEchoInfo "change mod of /opt/ograc/log/og_om"
    else
        logAndEchoError "change mod of /opt/ograc/log/og_om"
        exit 1
    fi
    chown -hR "${ograc_user}":"${ograc_group}" /opt/ograc/log/og_om
    if [ $? -eq 0 ]; then
        logAndEchoInfo "change owner of /opt/ograc/log/og_om"
    else
        logAndEchoError "change owner of /opt/ograc/log/og_om"
        exit 1
    fi
fi
