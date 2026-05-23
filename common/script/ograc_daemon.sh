#!/bin/bash

set +x
CURRENT_PATH=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SCRIPT_NAME=$(basename "${BASH_SOURCE[0]}")
ACTION_CONFIG="${CURRENT_PATH}/../../action/config.py"
if [ ! -f "${ACTION_CONFIG}" ]; then
    echo "[ERROR] new-flow config.py not found: ${ACTION_CONFIG}" >&2
    exit 1
fi
SHELL_ENV=$(python3 "${ACTION_CONFIG}" --shell-env 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "[ERROR] failed to load new-flow config from ${ACTION_CONFIG}" >&2
    exit 1
fi
eval "${SHELL_ENV}"

OGRAC_HOME="${OGRAC_HOME:-$(cd "${CURRENT_PATH}/../.." && pwd)}"
OGRAC_ACTION_DIR="${OGRAC_ACTION_DIR:-${OGRAC_HOME}/action}"
OGRAC_USER="${OGRAC_USER:-ograc}"
DEPLOY_DAEMON_LOG="${DEPLOY_DAEMON_LOG:-${OGRAC_HOME}/log/deploy/deploy_daemon.log}"
CMS_ENABLE_FLAG="${OGRAC_HOME}/cms/cfg/cms_enable"
CMS_CONFIG="${OGRAC_HOME}/cms/cfg/cms.json"
CMS_REG_SCRIPT="${OGRAC_ACTION_DIR}/cms/cms_reg.sh"
CMS_START_SCRIPT="${OGRAC_ACTION_DIR}/cms/cms_startup.py"
EXPORTER_APPCTL="${OGRAC_ACTION_DIR}/ograc_exporter/appctl.sh"
OGOM_APPCTL="${OGRAC_ACTION_DIR}/og_om/appctl.sh"
EXPORTER_EXEC="${OGRAC_HOME}/og_om/service/ograc_exporter/exporter/execute.py"
OGMGR_EXEC="${OGRAC_HOME}/og_om/service/ogmgr/uds_server.py"
CMS_MEM_LIMIT=95
LOOP_TIME=0.8
CMS_COUNT=0

source "${CURRENT_PATH}/log4sh.sh"

get_first_pid()
{
    pgrep -f "$1" | head -n 1
}

system_memory_used_percent()
{
    total_mem=$(free -m | awk '/^Mem:/ {print $2}')
    used_mem=$(free -m | awk '/^Mem:/ {print $3}')
    able_mem=$(free -m | awk '/^Mem:/ {print $7}')

    mem_usage=$(printf "%.2f" "$(echo "scale=2; ${used_mem} / ${total_mem} * 100" | bc)")
    mem_able=$(printf "%.2f" "$(echo "scale=2; ${able_mem} / ${total_mem} * 100" | bc)")
}

ensure_process()
{
    local process_pattern="$1"
    local appctl="$2"
    local name="$3"

    if [ -n "$(get_first_pid "${process_pattern}")" ]; then
        return 0
    fi

    logAndEchoInfo "[ograc daemon] ${name} is offline, begin to start ${name}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    sh "${appctl}" start
    logAndEchoInfo "[ograc daemon] start ${name} result: $?. [Line:${LINENO}, File:${SCRIPT_NAME}]"
}

cms_port_from_config()
{
    grep "_PORT" "${CMS_CONFIG}" 2>/dev/null | head -n 1 | awk -F'= ' '{print $2}'
}

refresh_iptables_for_cms()
{
    local cms_port="$1"
    local iptables_path

    iptables_path=$(command -v iptables 2>/dev/null)
    if [ -z "${iptables_path}" ] || [ -z "${cms_port}" ]; then
        return 0
    fi

    logAndEchoInfo "[ograc daemon] begin to refresh iptables for CMS port ${cms_port}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    iptables -D INPUT -p tcp --sport "${cms_port}" -j ACCEPT -w 60
    iptables -D FORWARD -p tcp --sport "${cms_port}" -j ACCEPT -w 60
    iptables -D OUTPUT -p tcp --sport "${cms_port}" -j ACCEPT -w 60
    iptables -I INPUT -p tcp --sport "${cms_port}" -j ACCEPT -w 60
    iptables -I FORWARD -p tcp --sport "${cms_port}" -j ACCEPT -w 60
    iptables -I OUTPUT -p tcp --sport "${cms_port}" -j ACCEPT -w 60
}

start_cms_in_background()
{
    local cms_port
    cms_port=$(cms_port_from_config)
    refresh_iptables_for_cms "${cms_port}"
    logAndEchoInfo "[ograc daemon] begin to start cms using ${OGRAC_USER}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    su -s /bin/bash - "${OGRAC_USER}" -c "python3 \"${CMS_START_SCRIPT}\" -start" >> "${DEPLOY_DAEMON_LOG}" 2>&1 &
    logAndEchoInfo "[ograc daemon] starting cms in background ${CMS_COUNT} times. [Line:${LINENO}, File:${SCRIPT_NAME}]"
}

if [ -f "${CMS_REG_SCRIPT}" ]; then
    su -s /bin/bash - "${OGRAC_USER}" -c "sh \"${CMS_REG_SCRIPT}\" enable"
fi

while :
do
    cms_pid=$(pgrep -u "${OGRAC_USER}" -f "cms server -start" | head -n 1)

    ensure_process "python3 ${EXPORTER_EXEC}" "${EXPORTER_APPCTL}" "ograc_exporter"
    ensure_process "python3 ${OGMGR_EXEC}" "${OGOM_APPCTL}" "og_om"

    system_memory_used_percent
    if [[ -n "${cms_pid}" ]]; then
        if [[ $(echo "${mem_usage} > ${CMS_MEM_LIMIT}" | bc) -eq 1 ]] || [[ $(echo "${mem_able} < 100-${CMS_MEM_LIMIT}" | bc) -eq 1 ]]; then
            top5_processes=$(ps aux --sort=-%mem | awk 'NR<=6{print $11, $2, $6/1024/1024}' | awk 'NR>1{printf "%s %s %.2fGB ", $1, $2, $3}')
            logAndEchoError "[ograc daemon] The top5 processes that occupy memory are: ${top5_processes}."
            if [ -f "${CMS_REG_SCRIPT}" ]; then
                su -s /bin/bash - "${OGRAC_USER}" -c "sh \"${CMS_REG_SCRIPT}\" disable"
            fi
            kill -9 "${cms_pid}"
            logAndEchoError "[ograc daemon] CMS abort due to memory pressure, usage=${mem_usage}%, available=${mem_able}%."
        fi
    fi

    if [ ! -f "${CMS_ENABLE_FLAG}" ]; then
        sleep "${LOOP_TIME}"
        continue
    fi

    cms_process_count=$(pgrep -u "${OGRAC_USER}" -f "cms server -start" | wc -l | tr -d ' ')
    cms_starting_count=$(pgrep -u "${OGRAC_USER}" -f "cms_startup.py.*-start" | wc -l | tr -d ' ')
    if [ "${cms_process_count}" -ne 1 ]; then
        if [ "${cms_starting_count}" -gt 0 ]; then
            logAndEchoInfo "[ograc daemon] cms is starting, startup process count is ${cms_starting_count}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            sleep "${LOOP_TIME}"
            continue
        fi
        if [ "${CMS_COUNT}" -le 9 ]; then
            logAndEchoInfo "[ograc daemon] cms process count is ${cms_process_count}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            CMS_COUNT=$((CMS_COUNT + 1))
            if [ "${cms_process_count}" -eq 0 ] && [ -f "${CMS_START_SCRIPT}" ]; then
                start_cms_in_background
            fi
        fi
        sleep "${LOOP_TIME}"
        continue
    fi

    CMS_COUNT=0
    sleep "${LOOP_TIME}"
done
