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

OGRAC_HOME="${OGRAC_HOME:-$(cd "${CURRENT_PATH}/../.." && pwd)}"
COMMON_SCRIPT_DIR="${COMMON_SCRIPT_DIR:-${CURRENT_PATH}}"
OGRAC_DAEMON_SCRIPT="${COMMON_SCRIPT_DIR}/ograc_daemon.sh"
DEPLOY_DAEMON_LOG="${DEPLOY_DAEMON_LOG:-${OGRAC_HOME}/log/deploy/deploy_daemon.log}"

source "${CURRENT_PATH}/log4sh.sh"
NFS_TIMEO=50
LOOP_TIME=5

get_cfg()
{
    python3 "${ACTION_CONFIG}" "$1"
}

mount_dir()
{
    local prefix="$1"
    local fs_name="$2"
    printf '%s/remote/%s_%s' "${OGRAC_DATA_ROOT}" "${prefix}" "${fs_name}"
}

check_port()
{
    local start_port="${NFS_PORT:-36729}"
    local i port listen_port occupied_proc_name

    for ((i=0; i<10; i++)); do
        port=$((start_port + i))
        listen_port=$(netstat -tunpl 2>/dev/null | awk -v target=":${port}" '$4 ~ target {print $4; exit}')
        occupied_proc_name=$(netstat -tunpl 2>/dev/null | awk -v target=":${port}" '$4 ~ target {print $7; exit}')
        if [[ -n "${listen_port}" && "${occupied_proc_name}" != "-" ]]; then
            logAndEchoError "Port ${port} is temporarily used by a non-nfs process. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            continue
        fi
        logAndEchoInfo "Port ${port} is available. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        NFS_PORT="${port}"
        return 0
    done

    logAndEchoError "Port range ${start_port}~$((start_port + 9)) is unavailable; update new-flow config. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    return 1
}

mount_once()
{
    local mount_path="$1"
    local remote_ip="$2"
    local fs_name="$3"
    local mount_opts="$4"

    [ -n "${remote_ip}" ] || return 0
    [ -n "${fs_name}" ] || return 0

    if mountpoint "${mount_path}" > /dev/null 2>&1; then
        return 0
    fi

    mkdir -p "${mount_path}"
    logAndEchoInfo "${mount_path} is not a mountpoint, begin to mount. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    mount -t nfs -o "${mount_opts}" "${remote_ip}:/${fs_name}" "${mount_path}"
    if [ $? -ne 0 ]; then
        logAndEchoError "mount ${mount_path} failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    logAndEchoInfo "mount ${mount_path} success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    return 0
}

mount_nfs()
{
    local storage_share_fs storage_archive_fs storage_metadata_fs storage_dbstor_fs
    local archive_logic_ip metadata_logic_ip share_logic_ip storage_logic_ip
    local kerberos_type deploy_mode base_opts mount_path

    storage_share_fs=$(get_cfg "storage_share_fs")
    storage_archive_fs=$(get_cfg "storage_archive_fs")
    storage_metadata_fs=$(get_cfg "storage_metadata_fs")
    storage_dbstor_fs=$(get_cfg "storage_dbstor_fs")
    archive_logic_ip=$(get_cfg "archive_logic_ip")
    metadata_logic_ip=$(get_cfg "metadata_logic_ip")
    share_logic_ip=$(get_cfg "share_logic_ip")
    storage_logic_ip=$(get_cfg "storage_logic_ip")
    kerberos_type=$(get_cfg "kerberos_key")
    deploy_mode=$(get_cfg "deploy_mode")

    if [[ -n "${storage_archive_fs}" ]]; then
        base_opts="timeo=${NFS_TIMEO},nosuid,nodev"
        if [[ "${deploy_mode}" != "file" && -n "${kerberos_type}" ]]; then
            base_opts="sec=${kerberos_type},${base_opts}"
        fi
        mount_path=$(mount_dir "archive" "${storage_archive_fs}")
        mount_once "${mount_path}" "${archive_logic_ip}" "${storage_archive_fs}" "${base_opts}" || return 1
    fi

    base_opts="timeo=${NFS_TIMEO},nosuid,nodev"
    if [[ "${deploy_mode}" != "file" && -n "${kerberos_type}" ]]; then
        base_opts="sec=${kerberos_type},${base_opts}"
    fi
    mount_path=$(mount_dir "metadata" "${storage_metadata_fs}")
    mount_once "${mount_path}" "${metadata_logic_ip}" "${storage_metadata_fs}" "${base_opts}" || return 1

    if [[ "${deploy_mode}" == "file" && -n "${storage_dbstor_fs}" ]]; then
        mount_path=$(mount_dir "storage" "${storage_dbstor_fs}")
        mount_once "${mount_path}" "${storage_logic_ip}" "${storage_dbstor_fs}" "vers=4.0,timeo=${NFS_TIMEO},nosuid,nodev" || return 1
    fi

    if [[ "${deploy_mode}" == "file" || -f "${OGRAC_HOME}/youmai_demo" ]]; then
        check_port || return 1
        sysctl fs.nfs.nfs_callback_tcpport="${NFS_PORT}" > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            logAndEchoError "Sysctl service is not ready. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            return 1
        fi
        mount_path=$(mount_dir "share" "${storage_share_fs}")
        mount_once "${mount_path}" "${share_logic_ip}" "${storage_share_fs}" "vers=4.0,timeo=${NFS_TIMEO},nosuid,nodev" || return 1
    fi
}

get_daemon_pid()
{
    pgrep -f "${OGRAC_DAEMON_SCRIPT}" | head -n 1
}

start_daemon()
{
    local deploy_mode ograc_pid

    deploy_mode=$(get_cfg "deploy_mode")
    if [[ "${deploy_mode}" != "dbstor" && "${deploy_mode}" != "dss" ]]; then
        mount_nfs || return 1
    fi

    ograc_pid=$(get_daemon_pid)
    if [ -n "${ograc_pid}" ]; then
        logAndEchoInfo "[ograc service] ograc_daemon pid is ${ograc_pid}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 0
    fi

    logAndEchoInfo "[ograc service] ograc_daemon is not found, begin to start ograc_daemon. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    nohup bash "${OGRAC_DAEMON_SCRIPT}" >> "${DEPLOY_DAEMON_LOG}" 2>&1 &
    sleep "${LOOP_TIME}"
    ograc_pid=$(get_daemon_pid)

    if [ -n "${ograc_pid}" ]; then
        logAndEchoInfo "[ograc service] start ograc_daemon success, pid=${ograc_pid}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 0
    fi

    logAndEchoError "[ograc service] start ograc_daemon failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    return 1
}

kill_daemon()
{
    local ograc_pid
    ograc_pid=$(get_daemon_pid)
    if [ -n "${ograc_pid}" ]; then
        logAndEchoInfo "[ograc service] ograc_daemon pid ${ograc_pid}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        kill -9 "${ograc_pid}"
        logAndEchoInfo "[ograc service] stop ograc_daemon result: $?. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    fi
}

stop_daemon()
{
    local i ograc_pid

    for ((i = 0; i < 10; i++)); do
        kill_daemon
        sleep "${LOOP_TIME}"
        ograc_pid=$(get_daemon_pid)
        [ -z "${ograc_pid}" ] && break
    done

    ograc_pid=$(get_daemon_pid)
    if [ -z "${ograc_pid}" ]; then
        logAndEchoInfo "[ograc service] stop ograc_daemon success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 0
    fi

    logAndEchoError "[ograc service] stop ograc_daemon failed, pid=${ograc_pid}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    return 1
}

ACTION=$1
case "${ACTION}" in
    start)
        start_daemon
        exit $?
        ;;
    stop)
        stop_daemon
        exit $?
        ;;
    *)
        logAndEchoError "Unsupported action: ${ACTION}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        exit 1
        ;;
esac
