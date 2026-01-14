#!/bin/bash
################################################################################
# 【功能说明】
# 1.appctl.sh由管控面调用
# 2.完成如下流程
#     服务初次安装顺序:pre_install->install->start->check_status
#     服务带配置安装顺序:pre_install->install->restore->start->check_status
#     服务卸载顺序:stop->uninstall
#     服务带配置卸载顺序:backup->stop->uninstall
#     服务重启顺序:stop->start->check_status

#     服务A升级到B版本:pre_upgrade(B)->stop(A)->update(B)->start(B)->check_status(B)
#                      update(B)=备份A数据，调用A脚本卸载，调用B脚本安装，恢复A数据(升级数据)
#     服务B回滚到A版本:stop(B)->rollback(B)->start(A)->check_status(A)->online(A)
#                      rollback(B)=根据升级失败标志调用A或是B的卸载脚本，调用A脚本安装，数据回滚特殊处理
# 3.典型流程路线：install(A)-upgrade(B)-upgrade(C)-rollback(B)-upgrade(C)-uninstall(C)
# 【返回】
# 0：成功
# 1：失败
#
# 【注意事项】
# 1.所有的操作需要支持失败可重入
################################################################################
set +x
#当前路径
CURRENT_PATH=$(dirname $(readlink -f $0))

OGOM_FILE_MOD_FILE=${CURRENT_PATH}/og_om_file_mod.sh
source ${OGOM_FILE_MOD_FILE}

#脚本名称
PARENT_DIR_NAME=$(pwd | awk -F "/" '{print $NF}')
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)

#依赖文件
source ${CURRENT_PATH}/../log4sh.sh

#组件名称
COMPONENT_NAME=og_om

OG_ECPORTER_CGROUP=/sys/fs/cgroup/memory/ograc_exporter
OGMGR_CGROUP=/sys/fs/cgroup/memory/ogmgr
OGMGR_MEM="2G"

INSTALL_NAME="install.sh"
UNINSTALL_NAME="uninstall.sh"
START_NAME="start.sh"
STOP_NAME="stop.sh"
PRE_INSTALL_NAME="pre_install.sh"
BACKUP_NAME="backup.sh"
RESTORE_NAME="restore.sh"
STATUS_NAME="check_status.sh"
UPGRADE_NAME="upgrade.sh"
ROLLBACK_NAME="rollback.sh"
POST_UPGRADE_NAME="post_upgrade.sh"
ROOT_EXECUTE=('install.sh' 'uninstall.sh' 'pre_install.sh' 'upgrade.sh' 'rollback.sh' 'post_upgrade.sh')

OGCTL_CMD='#!/bin/bash\nsu - ogmgruser -s /bin/bash -c "python3 /opt/ograc/og_om/service/ogcli/main.py $*"'

function correct_ctom_files_mod() {
    for file_path in ${!OGOM_BASIC_FILE_MODE_MAP[@]}; do
        chmod -R ${OGOM_BASIC_FILE_MODE_MAP[${file_path}]} ${file_path}
        if [ $? -ne 0 ]; then
            logAndEchoError "chmod ${OGOM_BASIC_FILE_MODE_MAP[$file_path]} to ${file_path} failed"
            exit 1
        fi
    done

    for file_path in ${!OGOM_FILE_R_MODE_MAP[@]}; do
        chmod -R ${OGOM_FILE_R_MODE_MAP[${file_path}]} ${file_path}
        if [ $? -ne 0 ]; then
            logAndEchoError "chmod ${OGOM_FILE_R_MODE_MAP[$file_path]} to ${file_path} failed"
            exit 1
        fi
    done

    for file_path in ${!OGOM_FILE_MODE_MAP[@]}; do
        chmod ${OGOM_FILE_MODE_MAP[$file_path]} $file_path
        if [ $? -ne 0 ]; then
            logAndEchoError "chmod ${OGOM_FILE_MODE_MAP[$file_path]} to ${file_path} failed"
            exit 1
        fi
    done

    return 0
}

function ogmgr_execute() {
    if id -u ogmgruser > /dev/null 2>&1; then
        su -s /bin/bash - ogmgruser -c "$1"
        return $?
    else
        logAndEchoError "user: ogmgruser not exist, change user failed"
        return 1
    fi
}

function usage()
{
    logAndEchoInfo "Usage: ${0##*/} {start|stop|install|uninstall|pre_install|pre_upgrade|check_status|upgrade}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    exit 1
}

function do_deploy()
{
    local script_name_param=$1
    local install_type=$2

    if [ ! -f  ${CURRENT_PATH}/${script_name_param} ]; then
        logAndEchoError "${COMPONENT_NAME} ${script_name_param} is not exist. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    if [[ "${ROOT_EXECUTE[@]}" =~ ${script_name_param} ]]; then
        # 安装og_om仅安装rpm包，root执行
        sh ${CURRENT_PATH}/${script_name_param} ${DIRECTORY_PATH}
        ret=$?
    else
        logAndEchoInfo "begin to execute ogmgr ${script_name_param}"
        ogmgr_execute "sh ${CURRENT_PATH}/${script_name_param}"
        ret=$?
    fi

    if [ $ret -ne 0 ]; then
        logAndEchoError "Execute ${COMPONENT_NAME} ${script_name_param} failed [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    logAndEchoInfo "Execute ${COMPONENT_NAME} ${script_name_param} success [Line:${LINENO}, File:${SCRIPT_NAME}]"
    return 0
}

function safety_upgrade()
{
    flock -n 506
    if [ $? -ne 0 ]; then
        logAndEchoError "another upgrade task is running. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi
    do_deploy ${UPGRADE_NAME}
} 506<>${CURRENT_PATH}/.upgrade_${COMPONENTNAME}

function safety_rollback()
{
    flock -n 506
    if [ $? -ne 0 ]; then
        logAndEchoError "another rollback task is running. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi
    do_deploy ${ROLLBACK_NAME}
} 506<>${CURRENT_PATH}/.rollback_${COMPONENTNAME}

function create_cgroup() {
    cgroup_name=$1
    logAndEchoInfo "begin to create cgroup: ${cgroup_name}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        if [[ -d ${cgroup_name} ]]; then
            rmdir ${cgroup_name}
        fi
        mkdir -p ${cgroup_name}
        if [ $? -ne 0 ]; then
            logAndEchoError "create cgroup: ${cgroup_name} failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            exit 1
        else
            logAndEchoInfo "create cgroup: ${cgroup_name} success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        fi
}

function add_pid_to_cgroup() {
    process_pid=$1
    cgroup_name=$2

    sh -c "echo ${process_pid} > ${cgroup_name}/tasks"
    if [ $? -ne 0 ]; then
        logAndEchoError "add pid to cgroup: ${cgroup_name} failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        exit 1
    else
        logAndEchoInfo "add pid to cgroup: ${cgroup_name} success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    fi
}

function limite_cgroup_mem() {
    mem_limited=$1
    cgroup_name=$2

    sh -c "echo ${mem_limited} > ${cgroup_name}/memory.limit_in_bytes"
    if [ $? -ne 0 ]; then
        logAndEchoError "cgroup: ${cgroup_name} memory limited failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        exit 1
    else
        logAndEchoInfo "cgroup: ${cgroup_name} memory limited success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    fi
}

function rm_cgroup() {
    cgroup_path=$1

    if [ -d ${cgroup_path} ]; then
            rmdir ${cgroup_path}
            if [ $? -ne 0 ]; then
                logAndEchoError "remove cgroup: ${cgroup_path} failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
                exit 1
            else
                logAndEchoInfo "remove cgroup: ${cgroup_path} success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            fi
        else
            logAndEchoInfo "cgroup: ${cgroup_path} not exist. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        fi
}

function correct_ctom_files_ownmod() {
    chown -R ogmgruser:ogmgruser /opt/ograc/og_om/service
    chmod -R 400 /opt/ograc/og_om/service
    chown ograc:ogracgroup /opt/ograc/og_om/service
    chown -R ograc:ogracgroup /opt/ograc/og_om/service/ograc_exporter
    chmod 770 /opt/ograc/og_om
    chmod 770 /opt/ograc/og_om/service
    chmod 700 /opt/ograc/og_om/service/ograc_exporter
    chmod 700 /opt/ograc/og_om/service/ograc_exporter/scripts
    chmod 700 /opt/ograc/og_om/service/ograc_exporter/exporter
    chmod 700 /opt/ograc/og_om/service/ograc_exporter/config
    chmod 755 /opt/ograc/og_om/service/ograc_exporter/query_storage_info
    chmod 600 /opt/ograc/og_om/service/ogcli/commands.json
    chmod 700 /opt/ograc/og_om/service/ogcli
    chmod 700 /opt/ograc/og_om/service/ogcli/params_factory
    chmod 700 /opt/ograc/og_om/service/ogmgr
    chmod 700 /opt/ograc/og_om/service/ogmgr/scripts
    chmod 700 /opt/ograc/og_om/service/ogmgr/checker
    chmod 700 /opt/ograc/og_om/service/ogmgr/logs_collection
    chmod 700 /opt/ograc/og_om/service/ogmgr/log_tool
    chmod 700 /opt/ograc/og_om/service/ogmgr/tasks
    chmod 700 /opt/ograc/og_om/service/ogmgr/common
    chmod 700 /opt/ograc/og_om/service/ogmgr/tasks/inspection
    chmod 600 /opt/ograc/og_om/service/ogmgr/format_note.json
    chmod 600 /opt/ograc/og_om/service/ogmgr/logs_collection/log_packing_progress.json
}

function mod_prepare() {
    # 修改og_om相关文件归属和权限
    sh ${CURRENT_PATH}/pre_install.sh ${ACTION}
    if [ $? -eq 0 ]; then
        logAndEchoInfo "og_om change mod and owner success"
    else
        logAndEchoInfo "og_om change mod and owner failed"
        exit 1
    fi
}

##################################### main #####################################
ACTION=$1
INSTALL_TYPE=$2
DIRECTORY_PATH=$3
case "$ACTION" in
    start)
        do_deploy ${START_NAME}
        exit $?
        ;;
    stop)
        do_deploy ${STOP_NAME}
        exit $?
        ;;
    pre_install)
        exit 0
        ;;
    install)
        echo -e ${OGCTL_CMD} > /usr/bin/ogctl && chmod 500 /usr/bin/ogctl # 创建ogctl文件
        correct_ctom_files_mod  # 修改action/og_om路径下文件权限
        mod_prepare  # 预安装：修改owner，进行文件cp
        do_deploy ${INSTALL_NAME} ${INSTALL_TYPE}
        if [ -f /opt/ograc/installed_by_rpm ]; then
            correct_ctom_files_ownmod
        fi
        chmod 600 /opt/ograc/og_om/service/ograc_exporter/config/get_logicrep_info.sql
        exit $?
        ;;
    uninstall)
        do_deploy ${UNINSTALL_NAME}
        if [ $? -ne 0 ]; then
            exit 1
        fi

        rm_cgroup ${OG_ECPORTER_CGROUP}
        rm_cgroup ${OGMGR_CGROUP}

        exit 0
        ;;
    check_status)
        do_deploy ${STATUS_NAME}
        exit $?
        ;;
    backup)
        exit 0
        ;;
    restore)
        exit 0
        ;;
    pre_upgrade)
        exit 0
        ;;
    upgrade_backup)
        exit 0
        ;;
    upgrade)
        correct_ctom_files_mod
        mod_prepare
        do_deploy ${UPGRADE_NAME}
        exit $?
        ;;
    post_upgrade)
        do_deploy ${POST_UPGRADE_NAME}
        exit $?
        ;;
    rollback)
        correct_ctom_files_mod
        mod_prepare
        do_deploy ${ROLLBACK_NAME}
        exit $?
        ;;
    *)
        usage
        ;;
esac
