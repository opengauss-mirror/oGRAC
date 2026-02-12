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

NFS_TIMEO=50
NFS_PORT=${NFS_PORT:-36729}

cfg_get() {
    "${PYTHON_BIN}" "${CONFIG_PY}" "$1"
}

check_port() {
    for ((i=0; i<10; i++)); do
        local port=$(("${NFS_PORT}" + "${i}"))
        local listen_port
        local occupied_proc_name
        listen_port=$(netstat -tunpl 2>/dev/null | grep "${port}" | awk '{print $4}' | awk -F':' '{print $NF}')
        occupied_proc_name=$(netstat -tunpl 2>/dev/null | grep "${port}" | awk '{print $7}' | awk 'NR==1 { print }')
        if [[ -n "${listen_port}" && ${occupied_proc_name} != "-" ]]; then
            logAndEchoError "Port ${port} has been temporarily used by a non-nfs process"
            continue
        fi
        logAndEchoInfo "Port[${port}] is available"
        NFS_PORT=${port}
        return 0
    done
    logAndEchoError "Port 36729~36738 has been temporarily used by a non-nfs process"
    exit 1
}

mount_nfs() {
    local storage_share_fs storage_archive_fs storage_metadata_fs
    local kerberos_type deploy_mode storage_dbstor_fs
    local archive_logic_ip metadata_logic_ip storage_logic_ip share_logic_ip

    storage_share_fs=$(cfg_get "storage_share_fs")
    storage_archive_fs=$(cfg_get "storage_archive_fs")
    storage_metadata_fs=$(cfg_get "storage_metadata_fs")
    kerberos_type=$(cfg_get "kerberos_key")
    deploy_mode=$(cfg_get "deploy_mode")

    if [[ -n "${storage_archive_fs}" ]]; then
        mountpoint "/mnt/dbdata/remote/archive_${storage_archive_fs}" > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            archive_logic_ip=$(cfg_get "archive_logic_ip")
            if [[ x"${deploy_mode}" != x"file" ]]; then
                mount -t nfs -o sec="${kerberos_type}",timeo=${NFS_TIMEO},nosuid,nodev \
                    "${archive_logic_ip}:/${storage_archive_fs}" "/mnt/dbdata/remote/archive_${storage_archive_fs}"
            else
                mount -t nfs -o timeo=${NFS_TIMEO},nosuid,nodev \
                    "${archive_logic_ip}:/${storage_archive_fs}" "/mnt/dbdata/remote/archive_${storage_archive_fs}"
            fi
            if [ $? -ne 0 ]; then
                logAndEchoError "mount archive_${storage_archive_fs} failed"
                exit 1
            fi
        fi
    fi

    if [[ -n "${storage_metadata_fs}" ]]; then
        mountpoint "/mnt/dbdata/remote/metadata_${storage_metadata_fs}" > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            metadata_logic_ip=$(cfg_get "metadata_logic_ip")
            if [[ x"${deploy_mode}" != x"file" ]]; then
                mount -t nfs -o sec="${kerberos_type}",timeo=${NFS_TIMEO},nosuid,nodev \
                    "${metadata_logic_ip}:/${storage_metadata_fs}" "/mnt/dbdata/remote/metadata_${storage_metadata_fs}"
            else
                mount -t nfs -o timeo=${NFS_TIMEO},nosuid,nodev \
                    "${metadata_logic_ip}:/${storage_metadata_fs}" "/mnt/dbdata/remote/metadata_${storage_metadata_fs}"
            fi
            if [ $? -ne 0 ]; then
                logAndEchoError "mount metadata_${storage_metadata_fs} failed"
                exit 1
            fi
        fi
    fi

    if [[ x"${deploy_mode}" == x"file" ]]; then
        storage_dbstor_fs=$(cfg_get "storage_dbstor_fs")
        storage_logic_ip=$(cfg_get "storage_logic_ip")
        mountpoint "/mnt/dbdata/remote/storage_${storage_dbstor_fs}" > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            mount -t nfs -o vers=4.0,timeo=${NFS_TIMEO},nosuid,nodev \
                "${storage_logic_ip}:/${storage_dbstor_fs}" "/mnt/dbdata/remote/storage_${storage_dbstor_fs}"
        fi
        if [ $? -ne 0 ]; then
            logAndEchoError "mount storage_${storage_dbstor_fs} failed"
            exit 1
        fi
    fi

    if [[ x"${deploy_mode}" == x"file" ]] || [[ -f "${OGRAC_HOME}/youmai_demo" ]]; then
        mountpoint "/mnt/dbdata/remote/share_${storage_share_fs}" > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            share_logic_ip=$(cfg_get "share_logic_ip")
            check_port
            sysctl fs.nfs.nfs_callback_tcpport="${NFS_PORT}" > /dev/null 2>&1
            if [ $? -ne 0 ]; then
                logAndEchoError "Sysctl service is not ready"
                exit 1
            fi
            mount -t nfs -o vers=4.0,timeo=${NFS_TIMEO},nosuid,nodev \
                "${share_logic_ip}:/${storage_share_fs}" "/mnt/dbdata/remote/share_${storage_share_fs}"
            if [ $? -ne 0 ]; then
                logAndEchoError "mount share_${storage_share_fs} failed"
                exit 1
            fi
        fi
    fi
}

get_daemon_pid() {
    ps -ef | grep -v grep | grep "${CURRENT_PATH}/ograc_daemon.sh" | awk '{print $2}'
}

LOOP_TIME=5

start_daemon() {
    local deploy_mode ograc_pid
    deploy_mode=$(cfg_get "deploy_mode")
    if [[ x"${deploy_mode}" != x"dbstor" ]] && [[ x"${deploy_mode}" != x"dss" ]]; then
        mount_nfs
    fi

    ograc_pid=$(get_daemon_pid)
    if [ -z "${ograc_pid}" ]; then
        logAndEchoInfo "[ograc service] ograc_daemon is not found, begin to start ograc_daemon."
        nohup sh "${CURRENT_PATH}/ograc_daemon.sh" > /dev/null 2>&1 &
        sleep ${LOOP_TIME}
        ograc_pid=$(get_daemon_pid)
        if [ -n "${ograc_pid}" ]; then
            logAndEchoInfo "[ograc service] start ograc_daemon success."
        else
            logAndEchoError "[ograc service] start ograc_daemon failed."
            return 1
        fi
    fi
    return 0
}

kill_daemon() {
    local ograc_pid
    ograc_pid=$(get_daemon_pid)
    if [ -n "${ograc_pid}" ]; then
        logAndEchoInfo "[ograc service] ograc_daemon pid ${ograc_pid}."
        kill -9 ${ograc_pid}
    fi
}

stop_daemon() {
    local ograc_pid
    for ((i=0; i<10; i++)); do
        kill_daemon
        sleep ${LOOP_TIME}
        ograc_pid=$(get_daemon_pid)
        if [ -z "${ograc_pid}" ]; then
            break
        fi
    done

    ograc_pid=$(get_daemon_pid)
    if [ -z "${ograc_pid}" ]; then
        logAndEchoInfo "[ograc service] stop ograc_daemon success."
    else
        logAndEchoError "[ograc service] stop ograc_daemon failed."
        return 1
    fi
    return 0
}

ACTION=$1
case "$ACTION" in
    start)
        start_daemon
        exit $?
        ;;
    stop)
        stop_daemon
        exit $?
        ;;
esac
