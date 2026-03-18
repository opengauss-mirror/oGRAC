#!/bin/bash

CURRENT_PATH=$(dirname $(readlink -f $0))
READINESS_FILE="/opt/ograc/readiness"
SINGLE_FLAG="/opt/ograc/ograc/cfg/single_flag"
CMS_ENABLE="/opt/ograc/cms/cfg/cms_enable"

source ${CURRENT_PATH}/docker_common/docker_log.sh

ograc_user=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_user"`
deploy_user=`python3 ${CURRENT_PATH}/../get_config_info.py "deploy_user"`
install_step=`python3 ${CURRENT_PATH}/../cms/get_config_info.py "install_step"`
deploy_group=`python3 ${CURRENT_PATH}/../get_config_info.py "deploy_group"`
run_mode=`python3 ${CURRENT_PATH}/get_config_info.py "M_RUNING_MODE"`
node_id=`python3 ${CURRENT_PATH}/get_config_info.py "node_id"`

ogracd_pid=$(ps -ef | grep ogracd | grep -v grep | awk 'NR==1 {print $2}')
cms_pid=$(ps -ef | grep cms | grep server | grep start | grep -v grep | awk 'NR==1 {print $2}')
ograc_daemon_pid=$(pgrep -f ograc_daemon)


# 手动停止ograc场景不触发飘逸和检查/cms未安装完成也不检查
if [[ -f /opt/ograc/stop.enable ]] || [[ x"${install_step}" != x"3" ]];then
    exit 1
fi
if [[ -f /opt/ograc/cms/res_disable ]];then
    logInfo "DB is manually stopped."
    exit 1
fi

# 启动项检查
if [[ "$1" == "startup-check" ]]; then
    if [[ -f "${READINESS_FILE}" ]]; then
        exit 0
    else
        exit 1
    fi
fi

function handle_failure() {
    if [[ -n "${cms_pid}" ]]; then
        manual_stop_count=$(su -s /bin/bash - ${ograc_user} -c "source ~/.bashrc && cms stat" | grep 'db' | awk '{if($5=="OFFLINE" && $1=='"${node_id}"'){print $5}}' | wc -l)
        if [[ -f "${CMS_ENABLE}" ]] && [[ ${manual_stop_count} -eq 1 ]]; then
            logInfo "CMS is manually stopped. Exiting."
            exit 1
        fi
    fi

    if [[ -f "${READINESS_FILE}" ]]; then
        python3 ${CURRENT_PATH}/delete_unready_pod.py
    fi
    exit 1
}

if [[ ! -f "${READINESS_FILE}" ]]; then
    exit 1
fi

if [[ -z "${ogracd_pid}" ]] && [[ "${run_mode}" == "ogracd_in_cluster" ]]; then
    logWarn "ogracd process not running in cluster mode."
    handle_failure
fi

if [[ -z "${cms_pid}" ]]; then
    logWarn "CMS process not found."
    handle_failure
fi

work_stat=$(su -s /bin/bash - ${ograc_user} -c 'cms stat' | awk -v nid=$((${node_id}+1)) 'NR==nid+1 {print $6}')
if [[ "${work_stat}" != "1" ]]; then
    logWarn "Work status is not 1."
    handle_failure
fi

if [[ -z "${ograc_daemon_pid}" ]]; then
    logInfo "ograc daemon not found. Attempting to start."
    if [[ -f /opt/ograc/stop.enable ]];then
        logInfo "ograc daemon not found. because to stop."
        exit 1
    fi
    /bin/bash /opt/ograc/common/script/ograc_service.sh start
    ograc_daemon_pid=$(pgrep -f ograc_daemon)
    if [[ -z "${ograc_daemon_pid}" ]]; then
        logError "Failed to start ograc daemon."
        handle_failure
    else
        logInfo "ograc daemon started successfully."
    fi
fi

exit 0