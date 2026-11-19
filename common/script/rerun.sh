#!/bin/bash
# Copyright (c) 2026 Huawei Technologies Co., Ltd.
# oGRAC is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

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

COMMON_SCRIPT_DIR="${COMMON_SCRIPT_DIR:-${CURRENT_PATH}}"
LOCK_NAME="${COMMON_SCRIPT_DIR}/rerun.${OGRAC_INSTANCE_TAG}.lock"

source "${CURRENT_PATH}/log4sh.sh"

run_systemctl()
{
    local action="$1"
    local unit="$2"
    systemctl "${action}" "${unit}"
    local ret=$?
    if [ ${ret} -eq 0 ]; then
        logAndEchoInfo "[rerun] systemctl ${action} ${unit} success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    else
        logAndEchoError "[rerun] systemctl ${action} ${unit} failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    fi
    return ${ret}
}

with_lock()
{
    if ( set -o noclobber; echo "$$" > "${LOCK_NAME}") 2> /dev/null; then
        trap 'rm -f "${LOCK_NAME}"; exit $?' INT TERM EXIT
        "$@"
        local ret=$?
        rm -f "${LOCK_NAME}"
        trap - INT TERM EXIT
        return ${ret}
    fi

    logAndEchoError "Failed to acquire lockfile: ${LOCK_NAME}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    [ -f "${LOCK_NAME}" ] && logAndEchoError "Held by $(cat "${LOCK_NAME}"). [Line:${LINENO}, File:${SCRIPT_NAME}]"
    return 1
}

start_units()
{
    logAndEchoInfo "[rerun] begin to start instance timers. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    systemctl daemon-reload || return 1
    run_systemctl start "${OGRAC_DAEMON_TIMER}" || return 1
    run_systemctl enable "${OGRAC_DAEMON_TIMER}" || return 1
    run_systemctl start "${OGRAC_LOGS_TIMER}" || return 1
    run_systemctl enable "${OGRAC_LOGS_TIMER}" || return 1
}

stop_units()
{
    logAndEchoInfo "[rerun] begin to stop instance timers. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    systemctl daemon-reload || return 1
    run_systemctl stop "${OGRAC_LOGS_TIMER}" || return 1
    run_systemctl disable "${OGRAC_LOGS_TIMER}" || return 1
    run_systemctl stop "${OGRAC_DAEMON_TIMER}" || return 1
    run_systemctl disable "${OGRAC_DAEMON_TIMER}" || return 1
    run_systemctl stop "${OGRAC_LOGS_SERVICE}" || true
    run_systemctl stop "${OGRAC_DAEMON_SERVICE}" || true
}

ACTION=$1
case "${ACTION}" in
    start)
        with_lock start_units
        exit $?
        ;;
    stop)
        with_lock stop_units
        exit $?
        ;;
    *)
        echo "action not support"
        exit 1
        ;;
esac
