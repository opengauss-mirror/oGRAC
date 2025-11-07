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

source "${CURRENT_PATH}"/../env.sh
#脚本名称
PARENT_DIR_NAME=$(pwd | awk -F "/" '{print $NF}')
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)

#组件名称
COMPONENT_NAME=dbstor

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
INIT_CONTAINER_NAME="init_container.sh"
RPM_UNPACK_PATH="/opt/ograc/image/oGRAC-RUN-CENTOS-64bit"
CILENT_TEST_PATH="/opt/ograc/dbstor/tools"

dbstor_home="/opt/ograc/dbstor"
dbstor_scripts="/opt/ograc/action/dbstor"
LOG_FILE="/opt/ograc/log/dbstor/install.log"
ograc_user_and_group="${ograc_user}":"${ograc_group}"

function usage()
{
    echo "Usage: ${0##*/} {start|stop|install|uninstall|pre_install|pre_upgrade|check_status|upgrade|rollback|upgrade_backup|init_container}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    exit 1
}

function do_deploy()
{
    local script_name_param=$1
    local uninstall_type=""
    local force_uninstall=""
    if [ $# -gt 1 ]; then
        uninstall_type=$2
    fi
    if [ $# -gt 2 ]; then
        force_uninstall=$3
    fi

    if [ ! -f  ${CURRENT_PATH}/${script_name_param} ]; then
        echo "${COMPONENT_NAME} ${script_name_param} is not exist. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    su -s /bin/bash - ${ograc_user} -c "cd ${CURRENT_PATH} && sh ${CURRENT_PATH}/${script_name_param} ${uninstall_type} ${force_uninstall}"

    ret=$?
    if [ $ret -eq 2 ]; then
        return 2
    fi
    if [ $ret -ne 0 ]; then
        echo "Execute ${COMPONENT_NAME} ${script_name_param} return ${ret}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    return 0
}

function chown_mod_scripts()
{
    echo -e "\nInstall User:${ograc_user}   Scripts Owner:${owner}"
    current_path_reg=$(echo $CURRENT_PATH | sed 's/\//\\\//g')
    scripts=$(ls ${CURRENT_PATH} | sed '/appctl.sh/d' | sed "s/^/${current_path_reg}\/&/g")
    chown -h ${ograc_user_and_group} ${scripts}
    chmod 755 ${CURRENT_PATH}
    chmod 400 ${CURRENT_PATH}/*.sh ${CURRENT_PATH}/*.py
}

function chown_pre_install_set()
{
    if [ ! -d /opt/ograc/action/dbstor ]; then
        mkdir -m 750 -p /opt/ograc/action/dbstor
    fi
    cp -arf ${CURRENT_PATH}/* /opt/ograc/action/dbstor/

    if [ ! -d /opt/ograc/dbstor ]; then
        mkdir -m 750 -p /opt/ograc/dbstor
    fi

    if [ ! -d /opt/ograc/log/dbstor ]; then
        mkdir -m 750 -p /opt/ograc/log/dbstor
    fi
    
    if [ ! -f ${LOG_FILE} ]; then
        touch ${LOG_FILE}
    fi

    for file in /opt/ograc/backup/files/*.ini
    do
        if [ -e "${file}" ];then
            chmod 600 "${file}"
        fi
    done
    for file in /opt/ograc/log/dbstor/*.log
    do
        if [ -e "${file}" ];then
            chmod 640 "${file}"
        fi
    done
    chown ${ograc_user_and_group} -hR /opt/ograc/dbstor
    chown ${ograc_user_and_group} -hR /opt/ograc/log/dbstor
}

# 预安装时提前检查是否存在信号量，如果有则删除
function check_sem_id() {
    ret=`lsipc -s -c | grep 0x20161227`
    if [ -n "$ret" ]; then
        arr=($ret)
        sem_id=${arr[1]}
        ipcrm -s $sem_id
    fi
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

function chown_install_set()
{
#    chown -h ${ograc_user_and_group} /mnt/dbdata/remote/share_${share_name}
#    if [ -d /mnt/dbdata/remote/share_${share_name}/node${node_id} ]; then
#        chmod 750 /mnt/dbdata/remote/share_${share_name}/node${node_id}
#        chown -hR ${ograc_user_and_group} /mnt/dbdata/remote/share_${share_name}/node${node_id}
#    fi
    if [ ! -d  /opt/ograc/dbstor/tools ]; then
        mkdir  -m 750 -p /opt/ograc/dbstor/tools
        cp -rf ${RPM_UNPACK_PATH}/client_test/* ${CILENT_TEST_PATH}/
        echo " client test copy success."
    fi
    if [ -f  /opt/ograc/dbstor/tools/dbstor_config.ini ]; then
        chmod 640 ${CILENT_TEST_PATH}/dbstor_config.ini
    fi
    if [ -f  /opt/ograc/dbstor/tools/client.cfg ]; then
        chmod 640 ${CILENT_TEST_PATH}/client.cfg
    fi
    #    拷贝kmc的动态库到目标目录
    if [ ! -d /opt/ograc/dbstor/lib ]; then
        mkdir -m 750 -p /opt/ograc/dbstor/lib
    fi
    cp -rf ${RPM_UNPACK_PATH}/kmc_shared/* /opt/ograc/dbstor/lib
    cp -rf ${RPM_UNPACK_PATH}/add-ons/ /opt/ograc/dbstor/
    chmod 550 ${CILENT_TEST_PATH}/*
    chmod 550 /opt/ograc/dbstor/lib/*
    chmod 550 /opt/ograc/dbstor/add-ons/*
    chmod 500 /opt/ograc/dbstor/lib/libcrypto.so
    chmod 500 /opt/ograc/dbstor/lib/libcrypto.so.1.1
    chmod 500 /opt/ograc/dbstor/lib/libkmc.so
    chown ${ograc_user_and_group} -hR /opt/ograc/dbstor
}

function check_rollback_files()
{
    backup_list=$1
    dest_dir=$2
    orig_dir=$3
    echo "check backup files in ${dest_dir} from ${orig_dir}"
    while read orig_path_line
    do
        record_orig_size=$(echo ${orig_path_line} | sed 's/ //g' | sed 's/\[//g' | awk -F ']' '{print $1}')
        orig_path=$(echo ${orig_path_line} | sed 's/ //g' | awk -F ']' '{print $2}')
        if [ -z ${orig_path} ];then
            continue
        fi
        if [[ ${orig_path} == *-\>* ]];then
            orig_path=$(echo ${orig_path} | awk -F '->' '{print $1}')
        fi

        if [[ ${orig_path} == ${orig_dir}* ]];then
            if [[ ${orig_path} == ${orig_dir}/log* ]];then
                continue
            fi
            orig_dir_reg=$(echo ${orig_dir} | sed 's/\//\\\//g')
            dest_dir_reg=$(echo ${dest_dir} | sed 's/\//\\\//g')
            dest_path=$(echo ${orig_path} | sed "s/^${orig_dir_reg}/${dest_dir_reg}/")
            if [ ! -e ${orig_path} ];then
                echo "Error: the corresponding file is not found : ${orig_path} -> ${dest_path}"
                return 1
            fi
            if [ -f ${orig_path} ];then
                orig_size=`ls -l ${orig_path} | awk '{print $5}'`
                dest_size=`ls -l ${dest_path} | awk '{print $5}'`
                if [ ${orig_size} != ${dest_size} ];then
                    echo "file: ${dest_path} ---> ${orig_path}"
                    echo "size: ${dest_size} ---> ${orig_size}"
                    echo "Error: the corresponding file size is different : ${orig_size} -> ${dest_size}"
                    return 1
                fi
                if [ ${orig_size} != ${record_orig_size} ];then
                    echo "file: ${dest_path} ---> ${orig_path}"
                    echo "size: ${dest_size} ---> ${record_orig_size}"
                    echo "Error: the corresponding file size is different from record orig size : ${record_orig_size} -> ${dest_size}"
                    return 1
                fi
            fi
        fi
    done < ${backup_list}
}

function record_dbstor_info() {
    backup_dir=$1
    echo "record the list of all dbstor module files before the upgrade."
    tree -afis ${dbstor_home} >> ${backup_dir}/dbstor/dbstor_home_files_list.txt

    echo "record the backup statistics information to file: backup.bak"
    echo "dbstor backup information for upgrade" >> ${backup_dir}/dbstor/backup.bak
    echo "time:
          $(date)" >> ${backup_dir}/dbstor/backup.bak
    echo "ograc_user:
              ${ograc_user_and_group}" >> ${backup_dir}/dbstor/backup.bak
    echo "dbstor_home:
              total_size=$(du -sh ${dbstor_home})
              total_files=$(tail ${backup_dir}/dbstor/dbstor_home_files_list.txt -n 1)" >> ${backup_dir}/dbstor/backup.bak
    return 0
}

function check_backup_files()
{
    backup_list=$1
    dest_dir=$2
    orig_dir=$3
    echo "check backup files in ${dest_dir} from ${orig_dir}"
    while read orig_path_line
    do
        record_orig_size=$(echo ${orig_path_line} | sed 's/ //g' | sed 's/\[//g' | awk -F ']' '{print $1}')
        orig_path=$(echo "${orig_path_line}" | sed 's/ //g' | awk -F ']' '{print $2}')
        if [ -z ${orig_path} ];then
            continue
        fi
        if [[ ${orig_path} == *-\>* ]];then
            orig_path=$(echo ${orig_path} | awk -F '->' '{print $1}')
        fi

        if [[ ${orig_path} == ${orig_dir}* ]];then
            if [[ ${orig_path} == ${orig_dir}/log* ]];then
                continue
            fi
            orig_dir_reg=$(echo ${orig_dir} | sed 's/\//\\\//g')
            dest_dir_reg=$(echo ${dest_dir} | sed 's/\//\\\//g')
            dest_path=$(echo ${orig_path} | sed "s/^${orig_dir_reg}/${dest_dir_reg}/")
            if [ ! -e ${dest_path} ];then
                echo "Error: the corresponding file is not found : ${orig_path} -> ${dest_path}"
                return 1
            fi
            if [ -f ${dest_path} ];then
                orig_size=`ls -l ${orig_path} | awk '{print $5}'`
                dest_size=`ls -l ${dest_path} | awk '{print $5}'`
                if [ ${orig_size} != ${dest_size} ];then
                    echo "file: ${orig_path} ---> ${dest_path}"
                    echo "size: ${orig_size} ---> ${dest_size}"
                    echo "Error: the corresponding file size is different : ${orig_size} -> ${dest_size}"
                    return 1
                fi
                if [ ${record_orig_size} != ${dest_size} ];then
                    echo "file: ${orig_path} ---> ${dest_path}"
                    echo "size: ${record_orig_size} ---> ${dest_size}"
                    echo "Error: the corresponding file size is different from record orig size : ${record_orig_size} -> ${dest_size}"
                    return 1
                fi
            fi
        fi
    done < ${backup_list}
}

function backup_dbstor_config_ini() {
    set -e
    backup_dir=$1
    echo "backup dbstor config ini"
    mkdir -m 750 -p ${backup_dir}/dbstor/conf/ogracd_cnf
    mkdir -m 750 -p ${backup_dir}/dbstor/conf/cms_cnf
    mkdir -m 750 -p ${backup_dir}/dbstor/conf/share_cnf
    mkdir -m 750 -p ${backup_dir}/dbstor/conf/tool_cnf
    cp -arf /opt/ograc/cms/dbstor/conf/dbs/* ${backup_dir}/dbstor/conf/cms_cnf
    cp -arf /mnt/dbdata/local/ograc/tmp/data/dbstor/conf/dbs/* ${backup_dir}/dbstor/conf/ogracd_cnf
    cp -arf ${dbstor_home}/tools/* ${backup_dir}/dbstor/conf/tool_cnf
    if [[ ! -f ${backup_dir}/dbstor/conf/tool_cnf/dbstor_config.ini ]];then
        cp -arf /opt/ograc/dbstor/tools/dbstor_config.ini  ${backup_dir}/dbstor/conf/tool_cnf
    fi
    set +e
}

function safety_upgrade_backup()
{
    set -e
    echo -e "\n======================== begin to backup dbstor module for upgrade ========================"

    old_ograc_owner=$(stat -c %U ${dbstor_home})
    if [[ ${version_first_number} -eq 2 ]];then
        ograc_user=${d_user}
    fi
    if [ ${old_ograc_owner} != ${ograc_user} ]; then
        echo "Error: the upgrade user is different from the installed user"
        return 1
    fi

    backup_dir=$1
    if [ -z "${backup_dir}" ]; then
        echo "Error: backup_dir is empty"
        return 1
    fi

    if [ -d ${backup_dir}/dbstor ];then
        echo "Error: ${backup_dir} alreadly exists, check whether data has been backed up"
        return 1
    fi

    echo "create bak dir for dbstor : ${backup_dir}/dbstor/"
    mkdir -m 750 ${backup_dir}/dbstor

    echo "backup dbstor home, from ${dbstor_home} to ${backup_dir}/dbstor/dbstor_home"
    mkdir -m 750 ${backup_dir}/dbstor/dbstor_home
    path_reg=$(echo ${dbstor_home} | sed 's/\//\\\//g')
    dbstor_backup=$(ls ${dbstor_home} | awk '{if($1!="log"){print $1}}' | sed "s/^/${path_reg}\//g")
    cp -arf ${dbstor_backup} ${backup_dir}/dbstor/dbstor_home

    record_dbstor_info ${backup_dir}

    echo "check that all files are backed up to ensure that no data is lost for safety upgrade and rollback"
    check_backup_files ${backup_dir}/dbstor/dbstor_home_files_list.txt ${backup_dir}/dbstor/dbstor_home ${dbstor_home}

    backup_dbstor_config_ini ${backup_dir}

    set +e
    echo "======================== backup dbstor module for upgrade successfully ========================"
    return 0
}

function safety_upgrade()
{
    set -e
    echo -e "\n======================== begin to upgrade dbstor module ========================"

    link_type=$(cat ${CURRENT_PATH}/../../config/deploy_param.json  |
              awk -F ',' '{for(i=1;i<=NF;i++){if($i~"link_type"){print $i}}}' |
              sed 's/ //g' | sed 's/:/=/1' | sed 's/"//g' |
              awk -F '=' '{print $2}')

    echo "update the tools files in ${dbstor_home}/tools"
    rm -rf ${dbstor_home}/tools/*
    cp -arf ${RPM_UNPACK_PATH}/client_test/* ${dbstor_home}/tools
    cp -arf ${UPGRADE_PATH}/dbstor/conf/tool_cnf/dbstor_config.ini ${dbstor_home}/tools/

    echo "update the lib files in ${dbstor_home}/lib"
    rm -rf ${dbstor_home}/lib/*
    cp -arf ${RPM_UNPACK_PATH}/kmc_shared/* ${dbstor_home}/lib

    echo "update the config files in ${dbstor_home}/conf/infra/config"
    dbstor_config_dir=${dbstor_home}/conf/infra/config
    rm -rf ${dbstor_config_dir}/node_config.xml
    if [ ${link_type} == 1 ] || [ ${link_type} == 2 ];then
        echo "link_type is rdma, copy node_config_rdma.xml"
        cp -arf ${RPM_UNPACK_PATH}/cfg/node_config_rdma.xml \
        ${dbstor_config_dir}/node_config.xml
    else
        echo "link_type is tcp, copy node_config_tcp.xml"
        cp -arf ${RPM_UNPACK_PATH}/cfg/node_config_tcp.xml \
        ${dbstor_config_dir}/node_config.xml
    fi
    rm -rf ${dbstor_config_dir}/osd.cfg
    cp -arf ${RPM_UNPACK_PATH}/cfg/osd.cfg \
        ${dbstor_config_dir}/osd.cfg

    chown ${ograc_user_and_group} -hR /opt/ograc/dbstor

    echo "update the dbstor scripts in ${dbstor_scripts}"
    if [ -d "${dbstor_scripts}" ]; then
        rm -rf ${dbstor_scripts}
        mkdir -p ${dbstor_scripts}
    else
        mkdir -p ${dbstor_scripts}
    fi

    cp -arf ${CURRENT_PATH}/* ${dbstor_scripts}
    chmod 400 ${dbstor_scripts}/*
    chmod 755 ${dbstor_scripts}
    chown -h ${ograc_user_and_group} ${dbstor_scripts}/*
    chown -h root:root ${dbstor_scripts}/appctl.sh

    echo "======================== upgrade dbstor module successfully ========================"
    set +e
    return 0
}

function rollback_dbstor_config_ini() {
    set -e
    backup_dir=$1
    echo "rollback dbstor config ini"
    cp -arf ${backup_dir}/dbstor/conf/cms_cnf/* /opt/ograc/cms/dbstor/conf/dbs/
    cp -arf ${backup_dir}/dbstor/conf/ogracd_cnf/* /mnt/dbdata/local/ograc/tmp/data/dbstor/conf/dbs/
    cp -arf ${backup_dir}/dbstor/conf/tool_cnf/* ${dbstor_home}/tools/
    set +e
}

function safety_rollback()
{
    set -e
    echo -e "\n======================== begin to rollback dbstor module ========================"

    version=$(cat ${CURRENT_PATH}/../../versions.yml |
              sed 's/ //g' | grep 'Version:' | awk -F ':' '{print $2}')

    backup_dir=$2
    if [ -z "${backup_dir}" ]; then
        echo "Error: backup_dir is empty"
        return 1
    fi

    if [ ! -d ${backup_dir}/ograc ];then
        echo "Error: backup_dir ${backup_dir}/ograc does not exist"
        return 1
    fi
    echo "rollback from backup dir ${backup_dir}, ograc version is ${version}"

    if [ ! -d ${backup_dir}/dbstor/dbstor_home ];then
        echo "Error: dir ${backup_dir}/dbstor/dbstor_home does not exist"
        return 1
    fi
    echo "rollback dbstor home ${dbstor_home}"
    path_reg=$(echo ${dbstor_home} | sed 's/\//\\\//g')
    dbstor_home_backup=$(ls ${dbstor_home} | awk '{if($1!="log"){print $1}}' | sed "s/^/${path_reg}\//g")
    rm -rf ${dbstor_home_backup}
    cp -arf ${backup_dir}/dbstor/dbstor_home/* ${dbstor_home}

    echo "check that all files are rolled back to ensure that no data is lost for safety rollback"
    check_rollback_files ${backup_dir}/dbstor/dbstor_home_files_list.txt ${backup_dir}/dbstor/dbstor_home ${dbstor_home}

    rollback_dbstor_config_ini ${backup_dir}

    echo "======================== rollback dbstor module successfully ========================"
    set +e
    return 0
}

##################################### main #####################################

deploy_user=$(cat ${CURRENT_PATH}/../../config/deploy_param.json |
              awk -F ',' '{for(i=1;i<=NF;i++){if($i~"deploy_user"){print $i}}}' |
              sed 's/ //g' | sed 's/:/=/1' | sed 's/"//g' |
              awk -F '=' '{print $2}')
d_user=$(echo ${deploy_user} | awk -F ':' '{print $2}')
owner=$(stat -c %U ${CURRENT_PATH})
#share_name=$(cat ${CURRENT_PATH}/../../config/deploy_param.json |
#              awk -F ',' '{for(i=1;i<=NF;i++){if($i~"storage_share_fs"){print $i}}}' |
#              sed 's/ //g' | sed 's/:/=/1' | sed 's/"//g' |
#              awk -F '=' '{print $2}')
node_id=$(cat ${CURRENT_PATH}/../../config/deploy_param.json |
              awk -F ',' '{for(i=1;i<=NF;i++){if($i~"node_id"){print $i}}}' |
              sed 's/ //g' | sed 's/:/=/1' | sed 's/"//g' |
              awk -F '=' '{print $2}')
ACTION=$1
FORCE_UNINSTALL=""
UNINSTALL_TYPE=""
BACKUP_PATH=""
UPGRADE_TYPE=""
ROLLBACK_TYPE=""
UPGRADE_PATH=""
ROLLBACK_PATH=""
if [ $# -gt 1 ]; then
    UNINSTALL_TYPE=$2
    BACKUP_PATH=$2
    UPGRADE_TYPE=$2
    ROLLBACK_TYPE=$2
fi
if [ $# -gt 2 ]; then
    FORCE_UNINSTALL=$3
    UPGRADE_PATH=$3
    ROLLBACK_PATH=$3
fi

if [ ! -d /opt/ograc/log/dbstor ]; then
    mkdir -m 750 -p /opt/ograc/log/dbstor
    chown ${ograc_user_and_group} -hR /opt/ograc/log/dbstor
fi

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
        check_sem_id
        check_ksf
        chown_mod_scripts
        chown_pre_install_set
        exit $?
        ;;
    install)
        chown_install_set
        do_deploy ${INSTALL_NAME}
        ret=$?
        exit ${ret}
        ;;
    uninstall)
        if [ -f /opt/ograc/log/dbstor/uninstall.log ];then
            chmod 640 /opt/ograc/log/dbstor/uninstall.log
        fi
        rm -rf /dev/shm/ograc* /dev/shm/FDSA* /dev/shm/cpuinfo_shm /dev/shm/cputimeinfo_shm /dev/shm/diag_server_usr_lock
        do_deploy ${UNINSTALL_NAME} ${UNINSTALL_TYPE} ${FORCE_UNINSTALL}
        exit $?
        ;;
    check_status)
        do_deploy ${STATUS_NAME}
        exit $?
        ;;
    backup)
        if [ ! -d /opt/ograc/backup/files ]; then
            mkdir -m 750 -p /opt/ograc/backup/files
        fi
        chown ${ograc_user_and_group} -hR /opt/ograc/backup
        do_deploy ${BACKUP_NAME}
        exit $?
        ;;
    restore)
        do_deploy ${RESTORE_NAME}
        exit $?
        ;;
    init_container)
        do_deploy ${INIT_CONTAINER_NAME}
        exit $?
        ;;
    pre_upgrade)
        exit 0
        ;;
    upgrade_backup)
        version_first_number=$(cat /opt/ograc/versions.yml |sed 's/ //g' | grep 'Version:' | awk -F ':' '{print $2}' | awk -F '.' '{print $1}')
        safety_upgrade_backup ${BACKUP_PATH}
        exit $?
        ;;
    upgrade)
        safety_upgrade ${UPGRADE_TYPE} ${UPGRADE_PATH}
        exit $?
        ;;
    rollback)
        safety_rollback ${ROLLBACK_TYPE} ${ROLLBACK_PATH}
        exit $?
        ;;
    post_upgrade)
        exit 0
        ;;
    *)
        usage
        ;;
esac
