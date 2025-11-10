#!/bin/bash
set +x

CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)
UPGRADE_MODE=$1
DORADO_IP=$2
SO_PATH=""
FILE_MOD_FILE=${CURRENT_PATH}/file_mod.sh
CMS_CHECK_FILE=${CURRENT_PATH}/fetch_cls_stat.py
UPDATE_CONFIG_FILE_PATH=${CURRENT_PATH}/update_config.py
SOURCE_ACTION_PATH=/opt/ograc/action
VERSION_FILE=/opt/ograc/versions.yml
OGRAC_STATUS=/opt/ograc/ograc/cfg/start_status.json
CONFIG_PATH=/opt/ograc/config
UPGRADE_SUCCESS_FLAG=/opt/ograc/pre_upgrade_${UPGRADE_MODE}.success
EXEC_SQL_FILE="${CURRENT_PATH}/ograc_common/exec_sql.py"
DV_LRPL_DETAIL="select DATABASE_ROLE from DV_LRPL_DETAIL;"
UPGRADE_MODE_LIS=("offline" "rollup")
OFFLINES_MODES=("dbstor" "dss")
dorado_user=""
dorado_pwd=""
node_id=""
do_snapshot_choice=""
upgrade_module_correct=false
# 滚动升级
CLUSTER_COMMIT_STATUS=("prepared" "commit")
storage_metadata_fs_path=""
cluster_and_node_status_path=""
cluster_status_flag=""
local_node_status_flag=""
local_node_status=""
modify_sys_table_flag=""
deploy_user=$(python3 ${CURRENT_PATH}/get_config_info.py "deploy_user")
deploy_group=$(python3 ${CURRENT_PATH}/get_config_info.py "deploy_group")
deploy_mode=$(python3 ${CURRENT_PATH}/get_config_info.py "deploy_mode")
CPU_CONFIG_INFO="/opt/ograc/ograc/cfg/cpu_config.json"
CLUSTER_PREPARED=3
NFS_TIMEO=50

source ${CURRENT_PATH}/log4sh.sh

if [[ x"${deploy_mode}" == x"file" ]];then
    python3 "${CURRENT_PATH}"/modify_env.py
    if [  $? -ne 0 ];then
        echo "Current deploy mode is ${deploy_mode}, modify env.sh failed."
    fi
fi

if [[ x"${deploy_mode}" == x"dss" ]]; then
    cp -arf ${CURRENT_PATH}/ograc_common/env_lun.sh ${CURRENT_PATH}/env.sh
fi

source ${CURRENT_PATH}/docker/dbstor_tool_opt_common.sh
source ${CURRENT_PATH}/env.sh

function rpm_check(){
    local count=2
    if [ x"${deploy_mode}" != x"file" ] && [ x"${deploy_mode}" != x"dss" ];then
      count=3
    fi
    rpm_pkg_count=$(ls "${CURRENT_PATH}"/../repo | wc -l)
    rpm_pkg_info=$(ls -l "${CURRENT_PATH}"/../repo)
    logAndEchoInfo "There are ${rpm_pkg_count} packages in repo dir, which detail is: ${rpm_pkg_info}"
    if [ ${rpm_pkg_count} -ne ${count} ]; then
        logAndEchoError "We have to have only ${count} rpm package,please check"
        exit 1
    fi
}

# 输入参数校验
function input_params_check() {
    logAndEchoInfo ">>>>> begin to check input params <<<<<"
    # 检查升级模式
    if [[ " ${UPGRADE_MODE_LIS[*]} " == *" ${UPGRADE_MODE} "* ]]; then
        logAndEchoInfo "pass upgrade mode check, current upgrade mode: ${UPGRADE_MODE}"
    else
        logAndEchoError "input upgrade module must be one of '${UPGRADE_MODE_LIS[@]}', instead of '${UPGRADE_MODE}'"
        exit 1
    fi

    # 离线升级需要检查阵列侧ip
    if [[ "${UPGRADE_MODE}" == "offline" ]] && [[ x"${deploy_mode}" != x"dss" ]]; then
        if [ -z "${DORADO_IP}" ]; then
            logAndEchoError "storage array ip must be provided"
            exit 1
        fi

        ping -c 1 ${DORADO_IP} > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            logAndEchoError "try to ping storage array ip '${DORADO_IP}', but failed"
            echo "Please check whether input is correct. If the network is disconnected, manually create snapshot according to the upgrade guide."
            read -p "Continue upgrade please input yes, otherwise exit:" do_snapshot_choice
            echo ""
            if [[ x"${do_snapshot_choice}" != x"yes" ]];then
                exit 1
            fi
        fi
    fi

    # 若使用入湖，需校验so依赖文件路径进行文件拷贝
    if [[ -f /opt/software/tools/logicrep/start.success ]]; then
        read -p "please input the so rely path of logicrep: " SO_PATH
        if [ ! -d "${SO_PATH}" ]; then
            logAndEchoInfo "pass upgrade mode check, current upgrade mode: ${UPGRADE_MODE}"
            exit 1
        else
            if [ -z "$(ls -A "${SO_PATH}")" ]; then
                logAndEchoInfo "pass upgrade mode check, current upgrade mode: ${UPGRADE_MODE}"
                exit 1
            fi
        fi
    fi
    logAndEchoInfo ">>>>> pass input params check <<<<<"
}

# 获取共享目录名称
function get_mnt_dir_name() {
    storage_share_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_share_fs"`
    storage_archive_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_archive_fs"`
    storage_metadata_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_metadata_fs"`
}
# 获取用户输入的阵列侧用户名ip等
function get_user_input() {
    read -p "please enter dorado_user: " dorado_user
    echo "dbstor_user is: ${dorado_user}"

    read -s -p "please enter dorado_pwd: " dorado_pwd
    echo ''
}

# 获取当前节点
function get_config_info() {
    deploy_mode=$(python3 "${CURRENT_PATH}"/get_config_info.py "deploy_mode")
    node_id=$(python3 ${CURRENT_PATH}/get_config_info.py "node_id")
    if [[ ${node} == x'' ]]; then
        logAndEchoError "obtain current node id error, please check file: config/deploy_param.json"
        exit 1
    fi

    logAndEchoInfo ">>>>> begin to init cluster and node status flag <<<<<"
    source_version=$(python3 ${CURRENT_PATH}/implement/get_source_version.py)
    if [ -z "${source_version}" ]; then
        logAndEchoError "failed to obtain source version"
        exit 1
    fi
    storage_metadata_fs_path="/mnt/dbdata/remote/metadata_${storage_metadata_fs}/upgrade/"
}

######################################################################
# 滚动升级ogbackup需要输入ininerDB路径、ip和port
######################################################################
function rollup_user_input() {
    read -p "please enter ogbackup storage path: " og_backup_main_path
    echo "ogbackup storage path: is: ${og_backup_main_path}"
    local path_length
    path_length=$(echo -n "${og_backup_main_path}" | wc -c)
    if [[ ${path_length} -gt 100 ]] || [[ ! -d ${og_backup_main_path} ]];then
        logAndEchoError "The length of the ogbackup path cannot exceed 100, and exists."
        exit 1
    fi

}

#  停止ograc, 离线升级不使用，滚动升级预留
function stop_ograc() {
    logAndEchoInfo "begin to stop ograc"
    sh "${SOURCE_ACTION_PATH}/stop.sh"
    if [ $? -ne 0 ]; then
        logAndEchoError "stop ograc failed"
        exit 1
    fi

    logAndEchoInfo "stop ograc success"
}

#  停止CMS, 离线升级不使用，滚动升级预留
function stop_cms() {
    kill -9 $(pidof cms)
    logAndEchoInfo "success stop cms"
}

#  检查ograc是否停止
function ograc_status_check() {
    logAndEchoInfo "begin to check ograc status"
    # 检查og_om状态
    su - ogmgruser -s /bin/bash -c "sh /opt/ograc/action/og_om/check_status.sh"
    if [ $? -eq 0 ]; then
        logAndEchoError "og_om is online, ograc status check failed"
        exit 1
    fi
    logAndEchoInfo "og_om pass the check"

    # 检查ograc_exporter状态
    py_pid=$(ps -ef | grep "python3 /opt/ograc/og_om/service/ograc_exporter/exporter/execute.py" | grep -v grep | awk '{print $2}')
    if [ ! -z "${py_pid}" ]; then
        logAndEchoError "ograc_exporter is online, ograc status check failed"
        exit 1
    fi
    logAndEchoInfo "ograc_exporter pass the check"

    # 检查ogracd状态
    ogracd_pid=$(pidof ogracd)
    if [ -n "${ogracd_pid}" ]; then
        logAndEchoError "ogracd is online, ograc status check failed"
        exit 1
    fi
    logAndEchoInfo "ogracd pass the check"

    # 检查cms状态
    cms_pid=$(ps -ef | grep cms | grep server | grep start | grep -v grep | awk 'NR==1 {print $2}')
    if [ -n "${cms_pid}" ]; then
        logAndEchoError "cms is online, ograc status check failed"
        exit 1
    fi
    logAndEchoInfo "cms pass the check"

    # 检查守护进程状态
    daemon_pid=$(ps -ef | grep -v grep | grep 'sh /opt/ograc/common/script/ograc_daemon.sh' | awk '{print $2}')
    if [ -n "${daemon_pid}" ]; then
        logAndEchoError "ograc_deamon is online, ograc status check failed"
        exit 1
    fi
    logAndEchoInfo "ograc_deamon pass the check"

    logAndEchoInfo "pass to check ograc status"
}

#  打快照
function creat_snapshot() {
    if [[ x"${do_snapshot_choice}" == x"yes" ]];then
        logAndEchoInfo " The ip[${DORADO_IP}] address is unreachable, No snapshot is required."
        return 0
    fi
    logAndEchoInfo "begin to create snapshot"
    get_user_input
    echo -e "${dorado_user}\n${dorado_pwd}" | python3 ${CURRENT_PATH}/storage_operate/do_snapshot.py create ${DORADO_IP} ${dircetory_path}
    if [ $? -ne 0 ]; then
        logAndEchoError "create snapshot failed"
        exit 1
    fi

    logAndEchoInfo "create snapshot success"
}

#######################################################################################
##  文件系统拆分
#######################################################################################
function check_dbstor_client_compatibility() {
    logAndEchoInfo "Begin to split dbstor file system."
    echo -e "${DORADO_IP}\n${dorado_user}\n${dorado_pwd}\n" | python3 "${CURRENT_PATH}"/storage_operate/split_dbstor_fs.py "upgrade" "${CURRENT_PATH}"/../config/deploy_param.json
    if [ $? -ne 0 ]; then
        logAndEchoError "Split dbstor file system failed, details see /opt/ograc/og_om/log/om_deploy.log"
        exit 1
    fi

    logAndEchoInfo "Split dbstor file system success"
}

function migrate_file_system() {
    logAndEchoInfo "Begin to split cms share file system."
    echo -e "${DORADO_IP}\n${dorado_user}\n${dorado_pwd}\n" | python3 "${CURRENT_PATH}"/storage_operate/migrate_file_system.py "upgrade" "${CURRENT_PATH}"/../config/deploy_param.json "${dircetory_path}"/config/deploy_param.json
    if [ $? -ne 0 ]; then
        logAndEchoError "Split cms file system failed, details see /opt/ograc/og_om/log/om_deploy.log"
        exit 1
    fi

    logAndEchoInfo "Split cms file system success"
}

#  备份老版本程序和配置
function do_backup() {
    logAndEchoInfo "begin to backup resource"
    source "${CURRENT_PATH}/upgrade_backup.sh"
    if [ $? -ne 0 ]; then
        return 0  # upgrade_backup 已经执行成功，跳过下面步骤
    fi

    for upgrade_module in "${UPGRADE_ORDER[@]}";
    do
        logAndEchoInfo "begin to backup ${upgrade_module}"
        sh "${CURRENT_PATH}/${upgrade_module}/appctl.sh" upgrade_backup ${dircetory_path}
        if [ $? -ne 0 ]; then
            logAndEchoError "${upgrade_module} upgrade_backup failed"
            logAndEchoError "For details, see the /opt/ograc/log/${upgrade_module}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            exit 1
        fi

        logAndEchoInfo "${upgrade_module} upgrade_backup success"
    done

    touch ${dircetory_path}/backup_success && chmod 400 ${dircetory_path}/backup_success
    if [ $? -ne 0 ]; then
        logAndEchoError "backup resource failed"
        exit 1
    fi
    find "${dircetory_path}/" -type f \( -name "*.txt" -o -name "*.cfg" -o -name "*.xml" \) -exec chmod 640 {} \;
    logAndEchoInfo "backup resource success"
}

function update_config() {
    # 更新认证开关参数
    su -s /bin/bash - "${ograc_user}" -c "python3 -B ${UPDATE_CONFIG_FILE_PATH} --component=ograc_ini --action=add --key=MES_SSL_SWITCH --value=FALSE"
    su -s /bin/bash - "${ograc_user}" -c "python3 -B ${UPDATE_CONFIG_FILE_PATH} --component=cms_ini --action=add --key=_CMS_MES_SSL_SWITCH --value=False"
    # 更新证书路径
    su -s /bin/bash - "${ograc_user}" -c "python3 -B ${UPDATE_CONFIG_FILE_PATH} --component=ograc_ini --action=add --key=MES_SSL_CRT_KEY_PATH --value=/opt/ograc/common/config/certificates"
    su -s /bin/bash - "${ograc_user}" -c "python3 -B ${UPDATE_CONFIG_FILE_PATH} --component=cms_ini --action=add --key=_CMS_MES_SSL_CRT_KEY_PATH --value=/opt/ograc/common/config/certificates"
    su -s /bin/bash - "${ograc_user}" -c "python3 -B ${UPDATE_CONFIG_FILE_PATH} --component=ograc_ini --action=update --key=MES_SSL_CRT_KEY_PATH --value=/opt/ograc/common/config/certificates"
    su -s /bin/bash - "${ograc_user}" -c "python3 -B ${UPDATE_CONFIG_FILE_PATH} --component=cms_ini --action=update --key=_CMS_MES_SSL_CRT_KEY_PATH --value=/opt/ograc/common/config/certificates"
    # 更新ks路径
    su -s /bin/bash - "${ograc_user}" -c "python3 -B ${UPDATE_CONFIG_FILE_PATH} --component=ograc_ini --action=add --key=KMC_KEY_FILES --value='(/opt/ograc/common/config/primary_keystore_bak.ks, /opt/ograc/common/config/standby_keystore_bak.ks)'"
    su -s /bin/bash - "${ograc_user}" -c "python3 -B ${UPDATE_CONFIG_FILE_PATH} --component=cms_ini --action=add --key=KMC_KEY_FILES --value='(/opt/ograc/common/config/primary_keystore_bak.ks, /opt/ograc/common/config/standby_keystore_bak.ks)'"

    
    su -s /bin/bash - "${ograc_user}" -c "python3 -B ${UPDATE_CONFIG_FILE_PATH} --component=cms_ini --action=add --key=CMS_LOG --value=/opt/ograc/log/cms"
    su -s /bin/bash - "${ograc_user}" -c "python3 -B ${UPDATE_CONFIG_FILE_PATH} --component=ograc_ini --action=update --key=LOG_HOME --value=/opt/ograc/log/ograc"
    su -s /bin/bash - "${ograc_user}" -c "python3 -B ${UPDATE_CONFIG_FILE_PATH} --component=ograc_ini --action=del --key=DAAC_TASK_NUM --value=256"
    su -s /bin/bash - "${ograc_user}" -c "python3 -B ${UPDATE_CONFIG_FILE_PATH} --component=ograc_ini --action=add --key=OGRAC_TASK_NUM --value=256"
    su -s /bin/bash - "${ograc_user}" -c "python3 -B ${UPDATE_CONFIG_FILE_PATH} --component=ograc --action=add --key=LOG_HOME --value=/opt/ograc/log/ograc"
    su -s /bin/bash - "${ograc_user}" -c "python3 -B ${UPDATE_CONFIG_FILE_PATH} --component=dbstor --action=add --key=DBS_LOG_PATH --value=/opt/ograc/log/dbstor"

}

function install_dbstor(){
    local arrch=$(uname -p)
    local dbstor_path="${CURRENT_PATH}"/../repo
    local dbstor_package_file=$(ls "${dbstor_path}"/DBStor_Client*_"${arrch}"*.tgz)
    if [ ! -f "${dbstor_package_file}" ];then
        logAndEchoError "${dbstor_package_file} is not exist."
        return 1
    fi

    dbstor_file_path=${CURRENT_PATH}/dbstor_file_path
    if [ -d "${dbstor_file_path}" ];then
        rm -rf "${dbstor_file_path}"
    fi
    mkdir -p "${dbstor_file_path}"
    tar -zxf "${dbstor_package_file}" -C "${dbstor_file_path}"

    local dbstor_test_file=$(ls "${dbstor_file_path}"/Dbstor_Client_Test*-"${arrch}"*-dbstor*.tgz)
    local dbstor_client_file=$(ls "${dbstor_file_path}"/dbstor_client*-"${arrch}"*-dbstor*.tgz)
    if [ ! -f "${dbstor_test_file}" ];then
        logAndEchoError "${dbstor_test_file} is not exist."
        return 1
    fi
    if [ ! -f "${dbstor_client_file}" ];then
        logAndEchoError "${dbstor_client_file} is not exist."
        return 1
    fi

    mkdir -p "${dbstor_file_path}"/client
    mkdir -p "${dbstor_file_path}"/client_test
    tar -zxf "${dbstor_test_file}" -C "${dbstor_file_path}"/client_test
    tar -zxf "${dbstor_client_file}" -C "${dbstor_file_path}"/client
    cp -arf "${dbstor_file_path}"/client/lib/* "${RPM_PACK_ORG_PATH}"/oGRAC-RUN-CENTOS-64bit/add-ons/
    cp -arf "${dbstor_file_path}"/client_test "${RPM_PACK_ORG_PATH}"/oGRAC-RUN-CENTOS-64bit
    if [ ! -d "${RPM_PACK_ORG_PATH}"/oGRAC-RUN-CENTOS-64bit/kmc_shared ];then
        mkdir -p "${RPM_PACK_ORG_PATH}"/oGRAC-RUN-CENTOS-64bit/kmc_shared
        cd "${RPM_PACK_ORG_PATH}"/oGRAC-RUN-CENTOS-64bit/kmc_shared || exit 1
        so_name=("libkmc.so.23.0.0" "libkmcext.so.23.0.0" "libsdp.so.23.0.0" "libsecurec.so" "libcrypto.so.1.1")
        link_name1=("libkmc.so.23" "libkmcext.so.23" "libsdp.so.23" "libcrypto.so.1.1")
        link_name2=("libkmc.so" "libkmcext.so" "libsdp.so" "libcrypto.so")
        ls -l "${dbstor_file_path}"/client/lib/kmc_shared
        for i in {0..2};do
            cp -f "${dbstor_file_path}"/client/lib/kmc_shared/"${so_name[$i]}" "${RPM_PACK_ORG_PATH}"/oGRAC-RUN-CENTOS-64bit/kmc_shared
            ln -s "${so_name[$i]}" "${link_name1[$i]}"
            ln -s "${link_name1[$i]}" "${link_name2[$i]}"
        done
        cp -f "${dbstor_file_path}"/client/lib/kmc_shared/"${so_name[4]}" "${RPM_PACK_ORG_PATH}"/oGRAC-RUN-CENTOS-64bit/kmc_shared
        ln -s "${link_name1[3]}" "${link_name2[3]}"
        cp -f "${dbstor_file_path}"/client/lib/kmc_shared/libsecurec.so "${RPM_PACK_ORG_PATH}"/oGRAC-RUN-CENTOS-64bit/kmc_shared
        cd - || exit 1
    fi    
    rm -rf "${dbstor_file_path}"
    return 0
}

function install_rpm()
{
    RPM_PATH=${CURRENT_PATH}/../repo/ograc-*.rpm
    RPM_UNPACK_PATH_FILE="/opt/ograc/image/ograc_connector/ogracKernel/oGRAC-DATABASE-CENTOS-64bit"
    RPM_PACK_ORG_PATH="/opt/ograc/image"

    if [ ! -f  "${CURRENT_PATH}"/../repo/ograc-*.rpm ]; then
        echo "ograc.rpm is not exist."
        exit 1
    fi

    rpm -ivh --replacepkgs ${RPM_PATH} --nodeps --force

    tar -zxf ${RPM_UNPACK_PATH_FILE}/oGRAC-RUN-CENTOS-64bit.tar.gz -C ${RPM_PACK_ORG_PATH}
    if [ x"${deploy_mode}" != x"file" ] && [ x"${deploy_mode}" != x"dss" ];then
        echo  "start replace rpm package"
        install_dbstor
        if [ $? -ne 0 ];then
            sh ${CURRENT_PATH}/uninstall.sh ${config_install_type}
            exit 1
        fi
    fi
    chmod -R 750 ${RPM_PACK_ORG_PATH}/oGRAC-RUN-CENTOS-64bit
    chown ${deploy_user}:${deploy_group} -hR ${RPM_PACK_ORG_PATH}/oGRAC-RUN-CENTOS-64bit
    chown root:root ${RPM_PACK_ORG_PATH}
}

function uninstall_rpm()
{
    RPM_PACK_ORG_PATH="/opt/ograc/image/oGRAC-RUN-CENTOS-64bit"
    result=`rpm -qa ograc | wc -l`
    if [ ${result} -ne 0 ]; then
        rpm -ev ograc --nodeps
    fi

    if [ -d ${RPM_PACK_ORG_PATH} ]; then
        rm -rf ${RPM_PACK_ORG_PATH}
    fi
}

function update_user_env() {
    grep 'export OGDB_DATA="/mnt/dbdata/local/ograc/tmp/data"' /home/"${ograc_user}"/.bashrc
    if [[ $? -ne 0 ]];then
        sed -i '$a export OGDB_DATA="/mnt/dbdata/local/ograc/tmp/data"' /home/"${ograc_user}"/.bashrc
    fi
    grep 'export OGDB_HOME="/opt/ograc/ograc/server"' /home/"${ograc_user}"/.bashrc
    if [[ $? -ne 0 ]];then
        sed -i '$a export OGDB_HOME="/opt/ograc/ograc/server"' /home/"${ograc_user}"/.bashrc
    fi
}

function check_and_update_cpu_config() {
    # 检查 绑核 文件是否存在，适配旧版本升级后默认绑核失效的问题
    if [ ! -f "${CPU_CONFIG_INFO}" ]; then
        su -s /bin/bash - "${ograc_user}" -c "python3 ${CURRENT_PATH}/ograc/bind_cpu_config.py init_config"
        su -s /bin/bash - "${ograc_user}" -c "python3 ${CURRENT_PATH}/ograc/bind_cpu_config.py"
    fi
}

#  升级
function do_upgrade() {
    logAndEchoInfo "begin to upgrade"
    correct_files_mod
    # 升级前删除掉遗留系统文件
    rm -rf /etc/systemd/system/ograc*.service
    rm -rf /etc/systemd/system/ograc*.timer
    # 更新系统定时任务文件
    cp -f ${CURRENT_PATH}/../config/*.service /etc/systemd/system/
    cp -f ${CURRENT_PATH}/../config/*.timer /etc/systemd/system/

    cp -fp ${CURRENT_PATH}/* /opt/ograc/action > /dev/null 2>&1
    cp -rfp ${CURRENT_PATH}/inspection /opt/ograc/action
    cp -rfp ${CURRENT_PATH}/implement /opt/ograc/action
    cp -rfp ${CURRENT_PATH}/logic /opt/ograc/action
    cp -rfp ${CURRENT_PATH}/storage_operate /opt/ograc/action
    cp -rfp ${CURRENT_PATH}/ograc_common /opt/ograc/action
    cp -rfp ${CURRENT_PATH}/docker /opt/ograc/action
    cp -rfp ${CURRENT_PATH}/utils /opt/ograc/action
    cp -rfp ${CURRENT_PATH}/../config /opt/ograc/
    cp -rfp ${CURRENT_PATH}/../common /opt/ograc/
    rm -rf /opt/ograc/repo/*
    cp -rf ${CURRENT_PATH}/../repo /opt/ograc/
    if [[ ${deploy_mode} == "file" ]];then
        cp -rfp ${CURRENT_PATH}/dbstor /opt/ograc/action
    fi
    chmod 400 /opt/ograc/repo/*
    logAndEchoInfo "om upgrade finished"

    uninstall_rpm
    install_rpm
    check_and_update_cpu_config

    for upgrade_module in "${UPGRADE_ORDER[@]}";
    do
        logAndEchoInfo "begin to upgrade ${upgrade_module}"
        sh "${CURRENT_PATH}/${upgrade_module}/appctl.sh" upgrade ${UPGRADE_MODE} ${dircetory_path} ${SO_PATH}
        if [ $? -ne 0 ]; then
            logAndEchoError "${upgrade_module} upgrade failed"
            logAndEchoError "For details, see the /opt/ograc/log/${upgrade_module}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            exit 1
        fi
        logAndEchoInfo "${upgrade_module} upgrade success"
    done
    # 修改巡检相关脚本
    chown -hR ${ograc_user}:${ograc_group} /opt/ograc/action/inspection
    # 更新配置文件
    update_user_env
    update_config
    local certificate_dir="/opt/ograc/common/config/certificates"
    local certificate_remote_dir="/mnt/dbdata/remote/share_${storage_share_fs}/certificates/node${node_id}"
    if [[ -d "${certificate_remote_dir}" ]];then
        if [ ! -d "${certificate_dir}" ];then
            mkdir -m 700 -p "${certificate_dir}"
            cp -arf "${certificate_remote_dir}"/ca.crt "${certificate_dir}"/ca.crt
            cp -arf "${certificate_remote_dir}"/mes.crt "${certificate_dir}"/mes.crt
            cp -arf "${certificate_remote_dir}"/mes.key "${certificate_dir}"/mes.key
            chown -hR "${ograc_user}":"${ograc_group}" "${certificate_dir}"
        fi
    fi
    if [[ -f /mnt/dbdata/local/ograc/tmp/data/cfg/zsql.ini ]];then
        mv /mnt/dbdata/local/ograc/tmp/data/cfg/zsql.ini /mnt/dbdata/local/ograc/tmp/data/cfg/ogsql.ini
    fi
}

#  修改公共文件mod
function correct_files_mod() {
    logAndEchoInfo "begin to correct files mod"
    source ${FILE_MOD_FILE}
    for file_path in ${!FILE_MODE_MAP[@]}; do
        if [ ! -f ${file_path} ]; then
            continue
        fi

        chmod ${FILE_MODE_MAP[$file_path]} $file_path
        if [ $? -ne 0 ]; then
            logAndEchoError "chmod ${FILE_MODE_MAP[$file_path]} ${file_path} failed"
            exit 1
        fi
    done
    # 其他模块使用升级后需要修改权限
    chown -h "${ograc_user}":"${ograc_group}" "${CURRENT_PATH}"/obtains_lsid.py
    chown -h "${ograc_user}":"${ograc_group}" "${CURRENT_PATH}"/implement/update_ograc_passwd.py
    chown -h "${ograc_user}":"${ograc_group}" "${CURRENT_PATH}"/update_config.py
    # 修改日志定期清理执行脚本权限
    chown -h "${ograc_user}":"${ograc_group}" ${CURRENT_PATH}/../common/script/logs_handler/do_compress_and_archive.py
    logAndEchoInfo "correct file mod success"
}

#  启动ograc
function start_ograc() {
    logAndEchoInfo "begin to start ograc"
    sh "${SOURCE_ACTION_PATH}/start.sh"
    if [ $? -ne 0 ]; then
        logAndEchoError "start ograc after upgrade failed"
        stop_ograc
        exit 1
    fi

    logAndEchoInfo "start ograc after upgrade success"
}

######################################################################
# 滚动升级场景，通过cms拉起ograc，避免其他节点正在进行reform，当前节点执行拉起失败
# 实现流程：
#        1、通过cms模块appctl.sh start 启动cms；
#        2、通过cms res -start db -node {node_id}拉起ogracd
######################################################################
function start_ogracd_by_cms() {
    logAndEchoInfo "begin to start cms"
    sh "${SOURCE_ACTION_PATH}"/cms/appctl.sh start
    if [ $? -ne 0 ]; then
        logAndEchoError "start cms after upgrade failed"
        exit 1
    fi
    logAndEchoInfo "begin to start ogracd"
    for ((i=1; i<=10; i++));do
        su -s /bin/bash - "${ograc_user}" -c "source ~/.bashrc&&cms res -start db -node ${node_id}"
        if [ $? -ne 0 ]; then
            logAndEchoError "start ogracd by cms failed, remaining Attempts: ${i}/10"
            sleep 20
            continue
        else
            # 修改ograc配置文件，后续start不会执行
            su -s /bin/bash - "${ograc_user}" -c "sed -i 's/\"start_status\": \"default\"/\"start_status\": \"started\"/' ${OGRAC_STATUS}"
            logAndEchoInfo "start ogracd by cms success"
            return
        fi
    done
    logAndEchoError "start ogracd by cms failed" && exit 1
}

#  升级后检查
function check_local_nodes() {
    logAndEchoInfo "begin to post upgrade check on local node"
    logAndEchoInfo "begin to check cms stat on local node"
    cms_result=$(python3 ${CMS_CHECK_FILE})
    cms_stat=${cms_result: 0-2: 1}
    if [[ ${cms_stat} != '0' ]]; then
        logAndEchoError "local node failed cms stat check"
        exit 1
    fi

    logAndEchoInfo "local node pass cms stat check"

    # 调用各模块post_upgrade
    for check_module in ${POST_UPGRADE_ORDER[@]};
    do
        logAndEchoInfo "begin post upgrade check for ${check_module}"
        sh "${CURRENT_PATH}/${check_module}/appctl.sh" post_upgrade
        if [ $? -ne 0 ]; then
            logAndEchoError "${check_module} post upgrade check failed"
            logAndEchoError "For details, see the /opt/ograc/log/${check_module}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            exit 1
        fi

        logAndEchoInfo "${check_module} post upgrade check success"
    done
    logAndEchoInfo "local node post upgrade check finished"
}

# 修改系统表
function modify_sys_tables() {
    modify_sys_table_flag="${storage_metadata_fs_path}/updatesys.true"
    modify_sys_tables_success="${storage_metadata_fs_path}/updatesys.success"
    modify_sys_tables_failed="${storage_metadata_fs_path}/updatesys.failed"
    systable_home="/opt/ograc/ograc/server/admin/scripts/rollUpgrade"
    bak_initdb_sql="${dircetory_path}/ograc/ograc_home/server/admin/scripts/initdb.sql"
    old_initdb_sql="${dircetory_path}/initdb.sql"
    new_initdb_sql="${systable_home}/../initdb.sql"
    # 无需修改系统表或者已经修改过系统表
    if [ ! -f "${modify_sys_table_flag}" ] || [ -f "${modify_sys_tables_success}" ]; then
        logAndEchoInfo "detected that the system tables have been modified or does not need to be modified"
        return 0
    fi
    node_ip="127.0.0.1"
    # 解决2.0升级3.0版本备份initdb.sql ograc用户没有读权限问题
    cp -arf "${bak_initdb_sql}" "${old_initdb_sql}"
    # 解决2.0版本initdb.sql版本号配置问题
    if [[ "$back_version" == "2.0.0"* ]];then
        sed -i "1355a --01" "${old_initdb_sql}"
    fi
    # 判断sql文件是否相同，如果不相同需要进行系统表升级，相同场景无需修改（避免B版本升级问题）
    diff "${old_initdb_sql}" "${new_initdb_sql}" > /dev/null
    if [[ $? != 0 ]];then
        logAndEchoInfo "modify sys tables start"
        # 2.0升级3.0场景，更新配置文件时已经输入了ogsql密码，此处不需要在重复输入，3.0需要单独输入
        if [[ "$back_version" != "2.0.0"* ]];then
            read -s -p "please enter ograc sys pwd: " ograc_sys_pwd
        fi
        echo ''
        chown "${ograc_user}":"${ograc_group}" "${old_initdb_sql}"
        echo -e "${ograc_sys_pwd}" | su -s /bin/bash - "${ograc_user}" -c "sh ${systable_home}/upgrade_systable.sh ${node_ip} ${systable_home}/../../../bin ${old_initdb_sql} ${new_initdb_sql} ${systable_home}"
        if [ $? -ne 0 ];then
            logAndEchoError "modify sys tables failed"
            touch "${modify_sys_tables_failed}" && chmod 600 "${modify_sys_tables_failed}"
            update_remote_status_file_path_by_dbstor "${modify_sys_tables_failed}"
            exit 1
        fi
        rm "${modify_sys_table_flag}"
        touch "${modify_sys_tables_success}" && chmod 600 "${modify_sys_tables_success}"
        update_remote_status_file_path_by_dbstor "${modify_sys_tables_success}"
        logAndEchoInfo "modify sys tables success"
    fi
}

# 滚动升级：更改集群/节点升级状态
function modify_cluster_or_node_status() {
    # 输入参数依次是：状态文件绝对路径、新的状态、集群或节点标志
    local cluster_or_node_status_file_path=$1
    local new_status=$2
    local cluster_or_node=$3
    local old_status=""

    if [ -n "${cluster_or_node_status_file_path}" ] && [ ! -f "${cluster_or_node_status_file_path}" ]; then
        logAndEchoInfo "rollup upgrade status of '${cluster_or_node}' does not exist."
    fi

    # 若新旧状态一致则不必更新
    if [ -f "${cluster_or_node_status_file_path}" ]; then
        old_status=$(cat ${cluster_or_node_status_file_path})
        if [ "${old_status}" == "${new_status}" ]; then
            logAndEchoInfo "the old status of ${cluster_or_node} is consistent with the new status, both are ${new_status}"
            return 0
        fi
    fi

    echo "${new_status}" > ${cluster_or_node_status_file_path}
    if [ $? -eq 0 ]; then
        update_remote_status_file_path_by_dbstor "${cluster_or_node_status_file_path}"
        logAndEchoInfo "change upgrade status of ${cluster_or_node} from '${old_status}' to '${new_status}' success."
        return 0
    else
        logAndEchoInfo "change upgrade status of ${cluster_or_node} from '${old_status}' to '${new_status}' failed."
        exit 1
    fi
}

# 滚动升级，升级准备步骤：初始化节点/集群状态标记文件名
function init_cluster_or_node_status_flag() {
    cluster_and_node_status_path="${storage_metadata_fs_path}/cluster_and_node_status"
    cluster_status_flag="${cluster_and_node_status_path}/cluster_status.txt"
    local_node_status_flag="${cluster_and_node_status_path}/node${node_id}_status.txt"
    # 支持重入
    if [ ! -d "${cluster_and_node_status_path}" ]; then
        mkdir -m 755 -p "${cluster_and_node_status_path}"
    fi
    logAndEchoInfo ">>>>> init cluster and node status flag success <<<<<"

    # 判断当前集群升级状态，若为prepared或commit则直接退出升级流程
    if [ -f "${cluster_status_flag}" ]; then
        cluster_status=$(cat ${cluster_status_flag})
        if [[ " ${CLUSTER_COMMIT_STATUS[*]} " == *" ${cluster_status} "* ]]; then
            logAndEchoInfo "the current cluster status is already ${cluster_status}, no need to execute the upgrade operation"
            exit 0
        fi
    fi

    # 升级提交之后支持升级重入
    commit_success_file="/mnt/dbdata/remote/metadata_${storage_metadata_fs}/upgrade/ograc_rollup_upgrade_commit_${source_version}.success"
    if [ -f "${commit_success_file}" ]; then
        rm "${commit_success_file}"
    fi
}

# 滚动升级，升级准备步骤：检查是否有其它节点处于升级状态
function check_if_any_node_in_upgrade_status() {
    logAndEchoInfo ">>>>> begin to check if anynode in rollup state  <<<<<"
    # 读取各节点升级状态文件，过滤掉当前节点的状态文件
    node_status_files=($(find "${cluster_and_node_status_path}" -type f | grep -v grep | grep -E "^${cluster_and_node_status_path}/node[0-9]+_status\.txt$" | grep -v "node${node_id}"))
    # 共享目录中无状态文件，则符合升级条件
    if [ ${#node_status_files[@]} -eq 0 ]; then
        return 0
    fi

    status_array=()
    for status in "${node_status_files[@]}";
    do
        status_array+=("$(cat ${status})")
    done

    # 对状态数组去重
    unique_status=($(printf "%s\n" "${status_array[@]}" | uniq))
    # 去重后长度若不为1则直接退出
    if [ ${#unique_status[@]} -ne 1 ]; then
        logAndEchoError "currently existing nodes are in the 'rollup' state, details: ${status_array[@]}"
        exit 1
    fi
    # 去重后元素不是rollup_success
    if [ "${unique_status[0]}" != "rollup_success" ]; then
        logAndEchoError "there are currently one or more nodes in the 'rollup' state"
        exit 1
    fi
    logAndEchoInfo ">>>>> check pass, currently no nodes are in rollup state  <<<<<"
}

# 滚动升级， 升级准备步骤：删除多余的ogback备份文件
function delete_redundant_files() {
    local file_path=$1
    local max_keep_num=$2

    logAndEchoInfo ">>>>> begin to delete redundant ogbackup files <<<<<"
    files_list=$(ls -lt "${file_path}" | grep "^d" | grep "ogbackup" | awk '{print $9}')
    files_count=$(echo "${files_list}" | wc -l)
    logAndEchoInfo "current files num: ${files_count}, max files num allowed: ${max_keep_num}"

    # 如果目录总数超过最大限制，则删除最久远的目录
    if [ "${files_count}" -gt "${max_keep_num}" ]; then
        files_to_delete=$(echo "${files_list}" | tail -n +$((${max_keep_num} + 1)))
        for dir in ${files_to_delete[@]}; do
            rm -rf "${file_path}/${dir}"
        done
    fi

    logAndEchoInfo ">>>>> delete redundant ogbackup files success <<<<<"
}

# 清除信号量
function clear_sem_id() {
    signal_num="0x20161227"
    sem_id=$(lsipc -s -c | grep ${signal_num} | grep -v grep | awk '{print $2}')
    if [ -n "${sem_id}" ]; then
        ipcrm -s ${sem_id}
        if [ $? -ne 0 ]; then
            logAndEchoError "clear sem_id failed"
            exit 1
        fi
        logAndEchoInfo "clear sem_id success"
    fi
}

# 容灾场景备端不需要进行备份
function check_dr_role() {
    role=$(echo -e "${DV_LRPL_DETAIL}" | su -s /bin/bash - ${ograc_user} -c \
    "source ~/.bashrc && export LD_LIBRARY_PATH=/opt/ograc/dbstor/lib:${LD_LIBRARY_PATH} \
    &&  python3 -B ${EXEC_SQL_FILE}" | grep "PHYSICAL_STANDBY")
    if [[ x"${role}" != x"" ]];then
        return 1
    fi
    return 0
}

# 滚动升级， 升级准备步骤：调用ogback工具备份数据
function call_ogbackup_tool() {
    logAndEchoInfo ">>>>> begin to call ogbackup tool <<<<<"
    check_dr_role
    if [ $? -ne 0 ];then
        logAndEchoInfo ">>>>> Current site is standby, no need to call ogbackup tool <<<<<"
        return 0
    fi
    # 支持ograc进程停止后，重入
    if [ -e "${storage_metadata_fs_path}/call_ctback_tool.success" ]; then
        logAndEchoInfo "the ogbackup tool has backed up the data successfully, no need to call it again"
        return 0
    fi
    echo "
     Please choose whether you need to use ogbackup for backup.
     If you haven't performed a backup before the upgrade, it is recommended to select step 1 to stop the upgrade process for backup.
     If the backup is already completed, please choose step 2 to continue the upgrade.
     If you haven't performed a backup before the upgrade, select step 3 during the upgrade process.
     Note: If you choose step 3, the current upgrade process duration will be extended to accommodate the backup time, so please ensure that the upgrade time window allows for it.
     1. stop upgrade and do ogbackup.
     2. No backup required and continue upgrade.
     3. do backup in upgrading."
    read -p "What's your choice, please input [1|2|3]:" ogbackup_choice
    if [[ ${ogbackup_choice} == '1' ]];then
        exit 0
    elif [[ ${ogbackup_choice} == "2" ]]; then
        return
    fi
    rollup_user_input
    # 创建备份目录
    cur_og_backup_path="${og_backup_main_path}/bak_$(date +"%Y%m%d%H%M%S")"
    mkdir -m 750 -p "${cur_og_backup_path}" && chown -hR "${ograc_user}:${ograc_common_group}" ${cur_og_backup_path}
    if [ $? -ne 0 ]; then
        logAndEchoError "create backup directory for calling og_backup_tool failed"
        exit 1
    fi

    # 清除信号量，防止调用ogback备份工具失败
    clear_sem_id

    # 调用ograc在线备份工具
    su -s /bin/bash - "${ograc_user}" -c "ogbackup --backup --target-dir=${cur_og_backup_path}
    if [ $? -ne 0 ]; then
        logAndEchoError "call ogbackup tool failed"
        exit 1
    fi

    # 备份目录下仅保留最多3分备份目录，超量则删除最为久远的备份目录
    max_backup_num_keep="3"
    delete_redundant_files "${og_backup_main_path}" "${max_backup_num_keep}"
    if [ $? -ne 0 ]; then
        logAndEchoError "delete redundant ogbackup files failed"
    fi

    logAndEchoInfo ">>>>> call ogbackup tool success <<<<<"
}

# 滚动升级：检查当前节点升级状态
function local_node_upgrade_status_check() {
    logAndEchoInfo ">>>>> begin to check local node upgrade status <<<<<"
    if [ -f "${local_node_status_flag}" ]; then
        cur_upgrade_status=$(cat ${local_node_status_flag})
        if [ "${cur_upgrade_status}" == "rollup_success" ]; then
            local_node_status="rollup_success"
            logAndEchoInfo "node_${node_id} has been upgraded successfully"
            return 0
        elif [ "${cur_upgrade_status}" == "rollup" ]; then
            logAndEchoInfo "node_${node_id} is in rollup state"
            return 0
        fi
    fi

    modify_cluster_or_node_status "${local_node_status_flag}" "rollup" "node_${node_id}"
    logAndEchoInfo ">>>>> pass check local node upgrade status <<<<<"
}

# 滚动升级：停止ograc各组件业务进程
function do_rollup_upgrade() {
    logAndEchoInfo ">>>>> begin to do rollup upgrade for node${node_id} <<<<<"

    stop_ograc
    stop_cms
    if [[ "${deploy_mode}" == "dss" ]]; then
        sh /opt/ograc/action/cms/appctl.sh start
        sh /opt/ograc/action/dss/appctl.sh start
        sh /opt/ograc/action/cms/appctl.sh stop
        sleep 10
    fi
    # 生成调用og_backup成功的标记文件，避免重入调用时失败
    touch "${storage_metadata_fs_path}/call_ctback_tool.success" && chmod 600 "${storage_metadata_fs_path}/call_ctback_tool.success"
    if [ $? -ne 0 ]; then
        logAndEchoError "create call_ctback_tool.success failed" && exit 1
    fi
    update_remote_status_file_path_by_dbstor "${storage_metadata_fs_path}/call_ctback_tool.success"
    do_backup
    do_upgrade
    # 启动ograc前执行一把清理，否则ograc会启动失败
    clear_sem_id
    start_ogracd_by_cms
    start_ograc
    check_local_nodes
    logAndEchoInfo ">>>>> do rollup upgrade for node${node_id} success <<<<<"
}

# 滚动升级：检查整个集群的升级状况
function cluster_upgrade_status_check() {
    logAndEchoInfo ">>>>> begin to check cluster upgrade status <<<<<"

    # 统计当前节点数目
    cms_ip=$(python3 ${CURRENT_PATH}/get_config_info.py "cms_ip")
    node_count=$(expr "$(echo "${cms_ip}" | grep -o ";" | wc -l)" + 1)

    # 读取各节点升级状态文件
    node_status_files=($(find "${cluster_and_node_status_path}" -type f | grep -v grep | grep -E "^${cluster_and_node_status_path}/node[0-9]+_status\.txt$"))
    status_array=()
    for status in "${node_status_files[@]}";
    do
        status_array+=("$(cat ${status})")
    done

    # 执行了升级操作的节点数少于计算节点数，直接退出
    if [ "${#status_array[@]}" != "${node_count}" ]; then
        logAndEchoInfo "currently only ${#status_array[@]} nodes have performed the rollup upgrade operation, totals:${node_count}."
        return 0
    fi

    # 对升级状态数组去重
    unique_status=($(printf "%s\n" "${status_array[@]}" | uniq))
    # 去重后长度若不为1则直接退出
    if [ ${#unique_status[@]} -ne 1 ]; then
        logAndEchoInfo "existing nodes have not been upgraded successfully, details: ${status_array[@]}"
        return 0
    fi
    # 去重后元素不是rollup_success
    if [ "${unique_status[0]}" != "rollup_success" ]; then
        logAndEchoError "none of the ${node_count} nodes were upgraded successfully"
        exit 1
    fi

    logAndEchoInfo ">>>>> all ${node_count} nodes were upgraded successfully, pass check cluster upgrade status <<<<<"
    return 3
}

# 滚动升级: 检查所有节点升级后的拉起和入集群情况
function post_upgrade_nodes_status() {
    logAndEchoInfo ">>>>> begin to check the startup and cluster status of all nodes after upgrading <<<<<"

    # 统计当前节点数目
    cms_ip=$(python3 ${CURRENT_PATH}/get_config_info.py "cms_ip")
    node_count=$(expr "$(echo "${cms_ip}" | grep -o ";" | wc -l)" + 1)

    cms_res=$(su -s /bin/bash - "${ograc_user}" -c "cms stat")

    # step1: 统计节点拉起情况
    start_array=()
    if [[ "${deploy_mode}" == "dss" ]]; then
        cms_res=$(su -s /bin/bash - "${ograc_user}" -c "cms stat | grep dss")
        readarray -t start_array <<< "$(echo "${cms_res}" | awk '{print $3}')"
    else
        cms_res=$(su -s /bin/bash - "${ograc_user}" -c "cms stat")
        readarray -t start_array <<< "$(echo "${cms_res}" | awk '{print $3}' | tail -n +$"2")"
    fi
    
    readarray -t start_array <<< "$(echo "${cms_res}" | awk '{print $3}' | tail -n +$"2")"
    if [ ${#start_array[@]} != "${node_count}" ]; then
        logAndEchoError "only ${#start_array[@]} nodes were detected, totals:${node_count}" && exit 1
    fi

    unique_start=($(printf "%s\n" "${start_array[@]}" | uniq))
    if [ ${#unique_start[@]} -ne 1 ]; then
        logAndEchoError "existing nodes have not been started successfully, details: ${start_array[@]}" && exit 1
    fi

    if [ "${unique_start[0]}" != "ONLINE" ]; then
        logAndEchoError "none of the ${node_count} nodes were started successfully" && exit 1
    fi

    logAndEchoInfo "all nodes started successfully"

    # step2: 统计节点加入集群的情况
    cluster_join=()
    readarray -t cluster_join <<< "$(echo "${cms_res}" | awk '{print $6}' | tail -n +$"2")"
    unique_join=($(printf "%s\n" "${cluster_join[@]}" | uniq))
    if [ ${#unique_join[@]} -ne 1 ]; then
        logAndEchoError "existing nodes have not joined the cluster successfully, details: ${unique_join[@]}" && exit 1
    fi

    if [ "${unique_join[0]}" != "1" ]; then
        logAndEchoError "none of the nodes joined the cluster" && exit 1
    fi

    logAndEchoInfo ">>>>> all nodes join the cluster successfully <<<<<"

}

function get_back_version() {
    back_version_detail=$(cat ${BACKUP_NOTE} | awk 'END {print}')
    fullback_version=($(echo ${back_version_detail} | tr ':' ' '))
    back_version=${fullback_version[0]}
}

function offline_upgrade() {
    ograc_status_check
    do_backup
    if [[ ${node_id} == '0' ]] && [[ ${deploy_mode} != "file" ]] && [[ ${deploy_mode} != "dss" ]]; then
        creat_snapshot
    fi
    get_back_version
    if [[ x"${deploy_mode}" == x"dbstor" ]]; then
        umount /mnt/dbdata/remote/share_"${storage_share_fs}"
        rm -rf /mnt/dbdata/remote/share_"${storage_share_fs}"
    fi
    do_upgrade

    start_ograc
    check_local_nodes
    if [[ ${node_id} == '0' ]]; then
        modify_sys_tables
    fi
    # 升级成功后删除升级检查成功标志文件
    if [ -f ${UPGRADE_SUCCESS_FLAG} ]; then
        rm -f ${UPGRADE_SUCCESS_FLAG}
    fi
    if [[ " ${OFFLINES_MODES[*]} " == *" ${deploy_mode} "* ]] && [[ -d /mnt/dbdata/remote/metadata_${storage_metadata_fs}/upgrade ]];then
        rm -rf /mnt/dbdata/remote/metadata_${storage_metadata_fs}/upgrade/*
    fi

}

function rollup_upgrade() {
    # 升级前先同步远端集群信息至本地
    update_local_status_file_path_by_dbstor
    # step1：升级前准备
    init_cluster_or_node_status_flag
    check_if_any_node_in_upgrade_status
    # 修改集群和节点状态文件为rollup
    modify_cluster_or_node_status "${cluster_status_flag}" "rollup" "cluster"
    local_node_upgrade_status_check
    call_ogbackup_tool
    # step2：节点升级
    if [ "${local_node_status}" != "rollup_success" ]; then
        do_rollup_upgrade
        modify_sys_tables
        modify_cluster_or_node_status "${local_node_status_flag}" "rollup_success" "node_${node_id}"
    fi
    # step3：
    # 节点升级后验证, 检查所有节点是否均升级成功；
    # 检查节点拉起情况，集群加入情况；
    # 升级后版本校验；
    # 更新集群状态
    cluster_upgrade_status_check
    ret=$?
    post_upgrade_nodes_status
    # 升级成功后删除升级检查成功标志文件
    if [ -f ${UPGRADE_SUCCESS_FLAG} ]; then
        rm -f ${UPGRADE_SUCCESS_FLAG}
    fi
    # 当前所有节点都升级完成后更新集群状态
    if [[ "${ret}" == "${CLUSTER_PREPARED}" ]];then
        modify_cluster_or_node_status "${cluster_status_flag}" "prepared" "cluster"
    fi
}

function show_ograc_version() {
    echo '#!/bin/bash
    set +x
    sn=$(dmidecode -s system-uuid)
    name=$(cat /etc/hostname)
    version=$(cat /opt/ograc/versions.yml | grep -oE "([0-9]+\.[0-9]+)" | sed "s/\.$//")
    echo SN                          : ${sn}
    echo System Name                 : ${name}
    echo Product Model               : ograc
    echo Product Version             : ${version}' > /usr/local/bin/show
    chmod 550 /usr/local/bin/show
}

function main() {
    logAndEchoInfo ">>>>> begin to upgrade, current upgrade mode: ${UPGRADE_MODE} <<<<<"
    input_params_check
    get_mnt_dir_name
    get_config_info
    rpm_check

    if [ ${UPGRADE_MODE} == "offline" ]; then
        offline_upgrade
    elif [ ${UPGRADE_MODE} == "rollup" ]; then
        rollup_upgrade
    fi
    # 升级成功后更新版本信息
    show_ograc_version
    cp -fp ${CURRENT_PATH}/../versions.yml /opt/ograc
    if [[ ${node_id} != '0' ]]; then
        rm -rf /mnt/dbdata/remote/metadata_${storage_metadata_fs}/upgrade/upgrade_node*
    fi
    logAndEchoInfo ">>>>> ${UPGRADE_MODE} upgrade performed successfully <<<<<"
    return 0
}

main