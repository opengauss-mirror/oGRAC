#!/bin/bash

set +x

CURRENT_PATH=$(dirname "$(readlink -f "$0")")
SCRIPT_NAME=$(basename "$0")
OGRAC_HOME=$(readlink -f "${CURRENT_PATH}/../..")
ACTION_DIR="${OGRAC_HOME}/action"
CONFIG_PY="${ACTION_DIR}/config.py"
PYTHON_BIN=${PYTHON_BIN:-python3}

if [ -f "${CONFIG_PY}" ]; then
    eval "$("${PYTHON_BIN}" "${CONFIG_PY}" --shell-env 2>/dev/null)" || true
fi

source "${CURRENT_PATH}/log4sh.sh"

OGRAC_USER=${OGRAC_USER:-ograc}
CMS_ENABLE_FLAG="${OGRAC_HOME}/cms/cfg/cms_enable"
CMS_CONFIG="${OGRAC_HOME}/cms/cfg/cms.json"
CMS_REG_SCRIPT="${ACTION_DIR}/cms/cms_reg.sh"
CMS_START_SCRIPT="${ACTION_DIR}/cms/cms_start2.sh"
EXPORTER_APPCTL="${ACTION_DIR}/ograc_exporter/appctl.sh"
OGOM_APPCTL="${ACTION_DIR}/og_om/appctl.sh"
EXPORTER_EXECUTE="${OGRAC_HOME}/og_om/service/ograc_exporter/exporter/execute.py"
OGMGR_UDS_SERVER="${OGRAC_HOME}/og_om/service/ogmgr/uds_server.py"
CMS_MEM_LIMIT=95
LOOP_TIME=0.8
CMS_COUNT=0

system_memory_used_percent() {
    total_mem=$(free -m | grep Mem | awk '{print $2}')
    used_mem=$(free -m | grep Mem | awk '{print $3}')
    able_mem=$(free -m | grep Mem | awk '{print $7}')
    mem_usage=$(printf "%.2f" "$(echo "scale=2; $used_mem / $total_mem * 100" | bc)")
    mem_able=$(printf "%.2f" "$(echo "scale=2; $able_mem / $total_mem * 100" | bc)")
}

get_user_pid() {
    local pattern=$1
    ps -fu "${OGRAC_USER}" | grep "${pattern}" | grep -vE '(grep|defunct)' | awk 'NR==1 {print $2}'
}

if [ -f "${CMS_REG_SCRIPT}" ]; then
    su -s /bin/bash - "${OGRAC_USER}" -c "sh ${CMS_REG_SCRIPT} enable"
fi

while :
do
    cms_pid=$(get_user_pid "cms server -start")

    ograc_exporter_pid=$(get_user_pid "python3 ${EXPORTER_EXECUTE}")
    if [ -z "${ograc_exporter_pid}" ]; then
        logAndEchoInfo "[ograc daemon] ograc_exporter is offline, begin to start ograc_exporter."
        sh "${EXPORTER_APPCTL}" start
    fi

    ogmgr_pid=$(get_user_pid "python3 ${OGMGR_UDS_SERVER}")
    if [ -z "${ogmgr_pid}" ]; then
        logAndEchoInfo "[ograc daemon] og_om is offline, begin to start og_om."
        sh "${OGOM_APPCTL}" start
    fi

    system_memory_used_percent
    if [[ -n "${cms_pid}" ]]; then
        if [[ $(echo "$mem_usage > ${CMS_MEM_LIMIT}" | bc) -eq 1 ]] || [[ $(echo "$mem_able < 100-${CMS_MEM_LIMIT}" | bc) -eq 1 ]]; then
            top5_processes=$(ps aux --sort=-%mem | awk 'NR<=6{print $11, $2, $6/1024/1024}' | awk 'NR>1{printf "%s %s %.2fGB ", $1, $2, $3}')
            logAndEchoError "[ograc daemon] top5 memory processes: ${top5_processes}."
            if [ -f "${CMS_REG_SCRIPT}" ]; then
                su -s /bin/bash - "${OGRAC_USER}" -c "sh ${CMS_REG_SCRIPT} disable"
            fi
            kill -9 "${cms_pid}"
            logAndEchoError "[ograc daemon] CMS ABORT because system memory usage is too high: ${mem_usage}%."
        fi
    fi

    if [ ! -f "${CMS_ENABLE_FLAG}" ]; then
        sleep ${LOOP_TIME}
        continue
    fi

    cms_process_info=$(ps -fu "${OGRAC_USER}" | grep "cms server -start" | grep -vE '(grep|defunct)')
    if [ -z "${cms_process_info}" ]; then
        cms_process_count=0
    else
        cms_process_count=$(echo "${cms_process_info}" | wc -l)
    fi

    if [ "${cms_process_count}" -ne 1 ]; then
        if [ "${CMS_COUNT}" -le 9 ]; then
            CMS_COUNT=$(expr "${CMS_COUNT}" + 1)
            if [ "${cms_process_count}" -eq 0 ]; then
                iptables_path=$(whereis iptables | awk -F: '{print $2}')
                line=$(grep "_PORT" "${CMS_CONFIG}" 2>/dev/null)
                cms_port=${line##*= }
                if [ -n "${iptables_path}" ] && [ -n "${cms_port}" ]; then
                    iptables -D INPUT -p tcp --sport "${cms_port}" -j ACCEPT -w 60
                    iptables -D FORWARD -p tcp --sport "${cms_port}" -j ACCEPT -w 60
                    iptables -D OUTPUT -p tcp --sport "${cms_port}" -j ACCEPT -w 60
                    iptables -I INPUT -p tcp --sport "${cms_port}" -j ACCEPT -w 60
                    iptables -I FORWARD -p tcp --sport "${cms_port}" -j ACCEPT -w 60
                    iptables -I OUTPUT -p tcp --sport "${cms_port}" -j ACCEPT -w 60
                fi
                logAndEchoInfo "[ograc daemon] begin to start cms use ${OGRAC_USER}."
                su -s /bin/bash - "${OGRAC_USER}" -c "sh ${CMS_START_SCRIPT} -start" >> "${DEPLOY_DAEMON_LOG}" 2>&1 &
            fi
        fi
        sleep ${LOOP_TIME}
    else
        CMS_COUNT=0
    fi

    sleep ${LOOP_TIME}
done

