#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)
LIMITS_CONFIG_PATH="/etc/security/limits.conf"
open_file_num=102400
node_count=$(python3 ${CURRENT_PATH}/get_config_info.py "cluster_scale")
ograc_in_container=$(python3 ${CURRENT_PATH}/get_config_info.py "ograc_in_container")
source ${CURRENT_PATH}/env.sh
source ${CURRENT_PATH}/log4sh.sh
START_MODE=$1

function initLimitsConfig() {
    nr_open=`cat /proc/sys/fs/nr_open`
    if [ ${open_file_num} -gt ${nr_open} ]; then
        logAndEchoWarn "openfile target ${open_file_num} exceeds fs.nr_open ${nr_open}, cap to nr_open and continue. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        open_file_num=${nr_open}
    fi
    if [ ! -f ${LIMITS_CONFIG_PATH} ]; then
        touch ${LIMITS_CONFIG_PATH}
    fi
    local tmpfile
    tmpfile=$(mktemp)
    awk -v user="${ograc_user}" \
        '!($1 == user && ($2 == "hard" || $2 == "soft") && $3 == "nofile")' \
        "${LIMITS_CONFIG_PATH}" > "${tmpfile}" || true
    cat "${tmpfile}" > "${LIMITS_CONFIG_PATH}"
    rm -f "${tmpfile}"
    echo "${ograc_user} hard nofile ${open_file_num}" >> ${LIMITS_CONFIG_PATH}
    echo "${ograc_user} soft nofile ${open_file_num}" >> ${LIMITS_CONFIG_PATH}
}

function checkOpenFiles() {
    exit_hard_nofile=`awk -v user="${ograc_user}" -v nofile="${open_file_num}" \
        '$1 == user && $2 == "hard" && $3 == "nofile" && $4 == nofile { found=1 } END { if (found) print "1" }' \
        "${LIMITS_CONFIG_PATH}"`
    exit_soft_nofile=`awk -v user="${ograc_user}" -v nofile="${open_file_num}" \
        '$1 == user && $2 == "soft" && $3 == "nofile" && $4 == nofile { found=1 } END { if (found) print "1" }' \
        "${LIMITS_CONFIG_PATH}"`
    if [[ ${exit_hard_nofile} = '' ]] || [[ ${exit_soft_nofile} = '' ]]; then
        logAndEchoError "failed to set openfile, please check file ${LIMITS_CONFIG_PATH}"
        exit 1
    fi
}

function systemd_timer_setter() {
    local timer_name=$1
    systemctl start ${timer_name} >> ${OM_DEPLOY_LOG_FILE} 2>&1
    if [ $? -eq 0 ];then
        logAndEchoInfo "start ${timer_name} success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        systemctl status ${timer_name} >> ${OM_DEPLOY_LOG_FILE} 2>&1
    else
        logAndEchoError "start ${timer_name} failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        logAndEchoError "For details, see the ${OM_DEPLOY_LOG_FILE}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    systemctl enable ${timer_name} >> ${OM_DEPLOY_LOG_FILE} 2>&1
    if [ $? -eq 0 ];then
        logAndEchoInfo "enable ${timer_name} success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        systemctl is-enabled ${timer_name} >> ${OM_DEPLOY_LOG_FILE} 2>&1
    else
        logAndEchoError "enable ${timer_name} failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        logAndEchoError "For details, see the ${OM_DEPLOY_LOG_FILE}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    return 0
}

# 自动配置openfile
deploy_user=$(python3 ${CURRENT_PATH}/get_config_info.py "deploy_user")
deploy_group=$(python3 ${CURRENT_PATH}/get_config_info.py "deploy_group")


if [ ! -f  ${LIMITS_CONFIG_PATH} ]; then
    logAndEchoInfo "the file ${LIMITS_CONFIG_PATH} not exist, creating it now."
    touch ${LIMITS_CONFIG_PATH}
fi
initLimitsConfig
checkOpenFiles

logAndEchoInfo "Begin to start. [Line:${LINENO}, File:${SCRIPT_NAME}]"
for lib_name in "${START_ORDER[@]}"
do
    logAndEchoInfo "start ${lib_name} . [Line:${LINENO}, File:${SCRIPT_NAME}]"
    sh ${CURRENT_PATH}/${lib_name}/appctl.sh start ${START_MODE} >> ${OM_DEPLOY_LOG_FILE} 2>&1
    if [ $? -ne 0 ]; then
        logAndEchoError "start ${lib_name} failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        logAndEchoError "For details, see the /opt/ograc/log/${lib_name}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        exit 1
    fi
    logAndEchoInfo "start ${lib_name} success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
done

logicrep_pid=$(ps -ef | grep "/opt/software/tools/logicrep/watchdog_logicrep.sh -n logicrep -N" | grep -v grep | awk '{print $2}')
if [[ -f /opt/software/tools/logicrep/start.success ]] && [[ -z ${logicrep_pid} ]];then
    su -s /bin/bash - "${ograc_user}" -c "nohup sh /opt/software/tools/logicrep/watchdog_logicrep.sh -n logicrep -N ${node_count} &" >> /opt/ograc/log/deploy/deploy.log 2>&1
fi

# 全部启动成功后，拉起守护进程 自动拉起cms和og_om
su -s /bin/bash - "${ograc_user}" -c "sh /opt/ograc/action/cms/cms_reg.sh enable"
sh /opt/ograc/common/script/ograc_service.sh start
if [ $? -eq 0 ];then
    logAndEchoInfo "start ograc_service success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
else
    logAndEchoError "start ograc_service failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    logAndEchoError "For details, see the ${OM_DEPLOY_LOG_FILE}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    exit 1
fi

if [ "$ograc_in_container" -eq 0 ]; then
    # 守护进程拉起后启动system服务 开机启动后拉起守护进程
    systemctl daemon-reload >> ${OM_DEPLOY_LOG_FILE} 2>&1

    sys_service_batch=(ograc.timer ograc_logs_handler.timer)
    for service in "${sys_service_batch[@]}"
    do
        systemd_timer_setter ${service}
        if [ $? -ne 0 ]; then
            exit 1
        fi
    done
fi

chmod 660 /dev/shm/ograc* > /dev/null 2>&1
chown -hR "${ograc_user}":"${deploy_group}" /dev/shm/ograc* > /dev/null 2>&1
logAndEchoInfo "start success"
exit 0
