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

#脚本名称
PARENT_DIR_NAME=$(pwd | awk -F "/" '{print $NF}')
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)

#组件名称
COMPONENTNAME=ograc

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
source ${CURRENT_PATH}/ogracd_cgroup_calculate.sh
LOG_FILE="/opt/ograc/log/ograc/ograc_deploy.log"

ograc_home=/opt/ograc/ograc
ograc_log=/opt/ograc/log/ograc
ograc_local=/mnt/dbdata/local/ograc
ograc_scripts=/opt/ograc/action/ograc
storage_metadata_fs=$(python3 ${CURRENT_PATH}/../get_config_info.py "storage_metadata_fs")

source ${CURRENT_PATH}/../env.sh
ograc_user="${ograc_user}":"${ograc_group}"

function usage()
{
    echo "Usage: ${0##*/} {start|stop|install|uninstall|pre_install|
                          pre_upgrade|check_status|upgrade|post_upgrade|rollback|upgrade_backup|init_container}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    exit 1
}

function do_deploy()
{
    local script_name_param=$1
    local uninstall_type=$2
    local force_uninstall=$3

    if [ ! -f  ${CURRENT_PATH}/${script_name_param} ]; then
        echo "${COMPONENTNAME} ${script_name_param} is not exist. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi
    su -s /bin/bash - ${user} -c "cd ${CURRENT_PATH} && sh ${CURRENT_PATH}/${script_name_param} ${uninstall_type} ${force_uninstall}"

    ret=$?
    if [ $ret -ne 0 ]; then
        echo "Execute ${COMPONENTNAME} ${script_name_param} return ${ret}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    return 0
}

function create_cgroup_path()
{
    if [[ -d /sys/fs/cgroup/memory/ogracd ]]; then
        rmdir /sys/fs/cgroup/memory/ogracd
    fi
    mkdir -p /sys/fs/cgroup/memory/ogracd
    echo "ogracd cgroup path created successfully."
}

function cgroup_config()
{
    ogracd_cgroup_config

    local ogracd_pid=$(pidof ogracd)
    sh -c "echo ${ogracd_pid} > /sys/fs/cgroup/memory/ogracd/tasks"
    if [ $? -eq 0 ]; then
        echo "ogracd pid : ${ogracd_pid} success"
    else
        echo "ogracd pid : ${ogracd_pid} failed"
    fi
}

function cgroup_clean()
{
    if [[ -d /sys/fs/cgroup/memory/ogracd ]]; then
        rmdir /sys/fs/cgroup/memory/ogracd
    fi
    echo "ogracd cgroup config is removed."
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

function check_ograc_status() {
    if [[ ${version_first_number} -eq 2 ]];then
        user=${d_user}
    fi
    echo "check ograc cluster status processes: cms stat"
    su -s /bin/bash - ${user} -c "source ~/.bashrc && cms stat"

    if [ X$node_id == X0 ];then
        online_stat_count=$(su -s /bin/bash - ${user} -c "source ~/.bashrc && cms stat" | grep 'db' | awk '{if($1==0){print $3}}' | grep 'ONLINE' | wc -l)
        work_stat_count=$(su -s /bin/bash - ${user} -c "source ~/.bashrc && cms stat" | grep 'db' | awk '{if($1==0){print $6}}' | grep '1' | wc -l)
    else
        online_stat_count=$(su -s /bin/bash - ${user} -c "source ~/.bashrc && cms stat" | grep 'db' | awk '{if($1==1){print $3}}' | grep 'ONLINE' | wc -l)
        work_stat_count=$(su -s /bin/bash - ${user} -c "source ~/.bashrc && cms stat" | grep 'db' | awk '{if($1==1){print $6}}' | grep '1' | wc -l)
    fi
    if [ ${online_stat_count} -ne 1 ];then
        echo "Error: the online status of the database is abnormal"
        return 1
    fi
    if [ ${work_stat_count} -ne 1 ];then
        echo "Error: the work status of the database is abnormal"
        return 1
    fi

    ograc_count=`ps -fu ${user} | grep "\-D ${ograc_local}/tmp/data" | grep -vE '(grep|defunct)' | wc -l`
    if [ ${ograc_count} -eq 1 ];then
        echo "ograc process is running, upgrade is normal at the moment"
    else
        echo "Error: the ogracd process is abnormal"
        return 1
    fi
    if [[ ${version_first_number} -eq 2 ]];then
        return 0
    fi
    su -s /bin/bash - "${user}" -c "source ~/.bashrc && export LD_LIBRARY_PATH=/opt/ograc/dbstor/lib:${LD_LIBRARY_PATH} && python3 -B ${CURRENT_PATH}/ograc_post_upgrade.py"
    if [ $? -ne 0 ]; then
        echo "Error: db status check failed."
        return 1
    fi
}

function pre_upgrade()
{
    set -e
    echo -e "\n======================== check ograc module status before upgrade ========================"
    echo "check ograc home: ${ograc_home}"
    if [ ! -d ${ograc_home}/server ];then
        echo "Error: ograc home server does not exist, ograc module may be not installed!"
        return 1
    fi

    echo "check ograc local data: ${ograc_local}/tmp/data"
    if [ ! -d ${ograc_local}/tmp/data ];then
        echo "Error: ograc local data dir does not exist, ograc module may be not installed!"
        return 1
    fi

    start_status=$(cat ${ograc_home}/cfg/start_status.json |
              awk -F ',' '{for(i=1;i<=NF;i++){if($i~"start_status"){print $i}}}' |
              sed 's/ //g' | sed 's/:/=/1' | sed 's/"//g' | sed 's/}//g' | sed 's/{//g' |
              awk -F '=' '{print $2}')
    db_create_status=$(cat ${ograc_home}/cfg/start_status.json |
          awk -F ',' '{for(i=1;i<=NF;i++){if($i~"db_create_status"){print $i}}}' |
          sed 's/ //g' | sed 's/:/=/1' | sed 's/"//g' | sed 's/}//g' | sed 's/{//g' |
          awk -F '=' '{print $2}')
    if [[ ${start_status} != "started" ]];then
        echo "Error: start ograc process before pre_upgrade!"
        return 1
    fi
    if [[ ${db_create_status} != "done" ]] && [[ ${node_id} == "0" ]];then
        echo "Error: the ograc database is not running and no database is created in node 0,
        you can directly install the ograc database instead of upgrading it！"
        return 1
    fi

    check_ograc_status
    echo "======================== check ograc module status before upgrade successfully ========================"
    set +e
    return 0
}

function post_upgrade()
{
    set -e
    echo -e "\n======================== begin to check ograc module status after upgrade ========================"
    echo "check ograc home: ${ograc_home}"
    ograc_home_files=`ls -l ${ograc_home}/server | wc -l`
    if [ ${ograc_home_files} == 0 ];then
        echo "Error: ograc home server files do not exist, ograc module may be not upgraded successfully!"
        return 1
    fi
    ls -l ${ograc_home}/server

    echo "check ograc scripts: ${ograc_scripts}"
    ograc_scripts_files=`ls -l ${ograc_scripts} | wc -l`
    if [ ${ograc_scripts_files} == 0 ];then
        echo "Error: ograc scripts do not exist, ograc module may be not upgraded successfully!"
        return 1
    fi
    ls -l ${ograc_scripts}

    echo "check ograc local data: ${ograc_local}/tmp/data"
    if [ ! -d ${ograc_local}/tmp/data ];then
        echo "Error: ograc local data dir does not exist, ograc module may be not upgraded successfully!"
        return 1
    fi

    check_ograc_status
    echo "======================== check ograc module status after upgrade successfully ========================"
    set +e
    return 0
}

function record_ograc_info() {
    backup_dir=$1
    echo "record the list of all ograc module files before the upgrade."
    tree -afis ${ograc_home} >> ${backup_dir}/ograc/ograc_home_files_list.txt
    tree -afis ${ograc_scripts} >> ${backup_dir}/ograc/ograc_scripts_files_list.txt
    tree -afis ${ograc_local} >> ${backup_dir}/ograc/ograc_local_files_list.txt

    echo "record the backup statistics information to file: backup.bak"
    echo "ograc backup information for upgrade" >> ${backup_dir}/ograc/backup.bak
    echo "time:
          $(date)" >> ${backup_dir}/ograc/backup.bak
    echo "deploy_user:
              ${ograc_user}" >> ${backup_dir}/ograc/backup.bak
    echo "ograc_home:
              total_size=$(du -sh ${ograc_home})
              total_files=$(tail ${backup_dir}/ograc/ograc_home_files_list.txt -n 1)" >> ${backup_dir}/ograc/backup.bak
    echo "ograc_scripts:
              total_size=$(du -sh ${ograc_scripts})
              total_files=$(tail ${backup_dir}/ograc/ograc_scripts_files_list.txt -n 1)" >> ${backup_dir}/ograc/backup.bak
    echo "ograc_local:
              total_size=$(du -sh ${ograc_local})
              total_files=$(tail ${backup_dir}/ograc/ograc_local_files_list.txt -n 1)" >> ${backup_dir}/ograc/backup.bak

    return 0
}

function safety_upgrade_backup()
{
    set -e
    echo -e "\n======================== begin to backup ograc module for upgrade ========================"

    old_ograc_owner=$(stat -c %U ${ograc_home})
    if [[ ${version_first_number} -eq 2 ]];then
        user=${d_user}
    fi
    if [ ${old_ograc_owner} != ${user} ]; then
        echo "Error: the upgrade user is different from the installed user"
        return 1
    fi

    backup_dir=$1

    if [ -d ${backup_dir}/ograc ];then
        echo "Error: ${backup_dir} alreadly exists, check whether data has been backed up"
        return 1
    fi

    echo "create bak dir for ograc : ${backup_dir}/ograc"
    mkdir -m 755 ${backup_dir}/ograc

    echo "backup ograc home, from ${ograc_home} to ${backup_dir}/ograc/ograc_home"
    mkdir -m 755 ${backup_dir}/ograc/ograc_home
    path_reg=$(echo ${ograc_home} | sed 's/\//\\\//g')
    ograc_home_backup=$(ls ${ograc_home} | awk '{if($1!="log"){print $1}}' | sed "s/^/${path_reg}\//g")
    cp -arf ${ograc_home_backup} ${backup_dir}/ograc/ograc_home

    echo "backup ograc scripts, from ${ograc_scripts} to ${backup_dir}/ograc/ograc_scripts"
    mkdir -m 755 ${backup_dir}/ograc/ograc_scripts
    cp -arf ${ograc_scripts}/* ${backup_dir}/ograc/ograc_scripts

    echo "backup ograc local, from ${ograc_local} to ${backup_dir}/ograc/ograc_local"
    mkdir -m 755 ${backup_dir}/ograc/ograc_local
    cp -arf ${ograc_local}/* ${backup_dir}/ograc/ograc_local

    record_ograc_info ${backup_dir}

    echo "check that all files are backed up to ensure that no data is lost for safety upgrade and rollback"
    check_backup_files ${backup_dir}/ograc/ograc_home_files_list.txt ${backup_dir}/ograc/ograc_home ${ograc_home}
    check_backup_files ${backup_dir}/ograc/ograc_scripts_files_list.txt ${backup_dir}/ograc/ograc_scripts ${ograc_scripts}
    check_backup_files ${backup_dir}/ograc/ograc_local_files_list.txt ${backup_dir}/ograc/ograc_local ${ograc_local}

    echo "======================== backup ograc module for upgrade successfully ========================"
    set +e
    return 0
}

function copy_ograc_dbstor_cfg()
{
    if [[ x"${deploy_mode}" == x"file" ]]; then
        return 0
    fi
    echo "update the ograc local config files for dbstor in ${ograc_local}"
    link_type=$1
    ograc_local_data_dir=${ograc_local}/tmp/data
    rm -rf ${ograc_local_data_dir}/dbstor/conf/infra/config/node_config.xml
    if [ ${link_type} == 1 ] || [ ${link_type} == 2 ];then
        echo "link_type is rdma, copy node_config_rdma.xml"
        cp -arf ${ograc_home}/server/cfg/node_config_rdma.xml \
        ${ograc_local_data_dir}/dbstor/conf/infra/config/node_config.xml
    else
        echo "link_type is tcp, copy node_config_tcp.xml"
        cp -arf ${ograc_home}/server/cfg/node_config_tcp.xml \
        ${ograc_local_data_dir}/dbstor/conf/infra/config/node_config.xml
    fi
    rm -rf ${ograc_local_data_dir}/dbstor/conf/infra/config/osd.cfg
    cp -arf ${ograc_home}/server/cfg/osd.cfg \
        ${ograc_local_data_dir}/dbstor/conf/infra/config/osd.cfg
}

function chown_mod_ograc_server()
{
    echo "chown and chmod the files in ${ograc_home}/server"
    chmod -R 700 ${ograc_home}/server
    find ${ograc_home}/server/add-ons -type f | xargs chmod 500
    find ${ograc_home}/server/admin -type f | xargs chmod 400
    find ${ograc_home}/server/bin -type f | xargs chmod 500
    find ${ograc_home}/server/lib -type f | xargs chmod 500
    find ${ograc_home}/server/cfg -type f | xargs chmod 600
    chmod 750 ${ograc_home}/server
    chmod 750 ${ograc_home}/server/admin
    chmod 750 ${ograc_home}/server/admin/scripts
    chmod 400 ${ograc_home}/server/package.xml
    chown -hR ${ograc_user} ${ograc_home}
    return 0
}

function update_ograc_server()
{
    echo "update the server files in ${ograc_home}/server"
    RPM_PACK_ORG_PATH=/opt/ograc/image
    ograc_pkg_file=${RPM_PACK_ORG_PATH}/oGRAC-RUN-CENTOS-64bit
    rm -rf ${ograc_home}/server/*
    cp -arf ${ograc_pkg_file}/add-ons ${ograc_pkg_file}/admin ${ograc_pkg_file}/bin \
       ${ograc_pkg_file}/cfg ${ograc_pkg_file}/lib ${ograc_pkg_file}/package.xml ${ograc_home}/server

    if [[ x"${deploy_mode}" == x"file" ]]; then
        return 0
    fi

    link_type=$1
    if [ ${link_type} == 1 ];then
        echo "link_type is rdma"
        cp -arf ${ograc_home}/server/add-ons/mlnx/lib* ${ograc_home}/server/add-ons/
    elif [ ${link_type} == 0 ];then
        cp -arf ${ograc_home}/server/add-ons/nomlnx/lib* ${ograc_home}/server/add-ons/
        echo "link_type is tcp"
    else
        cp -arf ${ograc_home}/server/add-ons/1823/lib* ${ograc_home}/server/add-ons/
        echo "link_type is rdma_1823"
    fi
    cp -arf ${ograc_home}/server/add-ons/kmc_shared/lib* ${ograc_home}/server/add-ons/
    return 0
}

function update_ograc_scripts() {
    echo "update the ograc scripts in ${ograc_scripts}, except start_status.json"
    path_reg=$(echo ${ograc_scripts} | sed 's/\//\\\//g')
    ograc_scripts_upgrade=$(ls ${ograc_scripts} | awk '{if($1!="start_status.json"){print $1}}' | sed "s/^/${path_reg}\/&/g")
    path_reg=$(echo ${CURRENT_PATH} | sed 's/\//\\\//g')
    ograc_scripts_upgrade=$(ls ${CURRENT_PATH} | awk '{if($1!="start_status.json"){print $1}}' | sed "s/^/${path_reg}\//g")
    cp -arf ${ograc_scripts_upgrade} ${ograc_scripts}
    return 0
}

function safety_upgrade()
{
    set -e
    echo -e "\n======================== begin to upgrade ograc module ========================"

    link_type=$(cat ${CURRENT_PATH}/../../config/deploy_param.json  |
          awk -F ',' '{for(i=1;i<=NF;i++){if($i~"link_type"){print $i}}}' |
          sed 's/ //g' | sed 's/:/=/1' | sed 's/"//g' |
          awk -F '=' '{print $2}')
    deploy_mode=$(python3 ${CURRENT_PATH}/get_config_info.py "deploy_mode")

    update_ograc_server ${link_type}

    chown_mod_ograc_server

    copy_ograc_dbstor_cfg ${link_type}

    update_ograc_scripts

    echo "======================== upgrade ograc module successfully ========================"
    set +e
    return 0
}

function safety_rollback()
{
    set -e
    echo -e "\n======================== begin to rollback ograc module ========================"

    version=$(cat ${CURRENT_PATH}/../../versions.yml |
              sed 's/ //g' | grep 'Version:' | awk -F ':' '{print $2}')
    backup_dir=$2
    if [ ! -d ${backup_dir}/ograc ];then
        echo "Error: backup_dir ${backup_dir}/ograc does not exist"
        return 1
    fi
    echo "rollback from backup dir ${backup_dir}, ograc version is ${version}"

    echo "rollback ograc home ${ograc_home}"
    if [ ! -d ${backup_dir}/ograc/ograc_home ];then
        echo "Error: dir ${backup_dir}/ograc/ograc_home does not exist"
        return 1
    fi
    path_reg=$(echo ${ograc_home} | sed 's/\//\\\//g')
    ograc_home_backup=$(ls ${ograc_home} | awk '{if($1!="log"){print $1}}' | sed "s/^/${path_reg}\//g")
    rm -rf ${ograc_home_backup}
    cp -arf ${backup_dir}/ograc/ograc_home/* ${ograc_home}

    echo "rollback ograc scripts ${ograc_scripts}"
    if [ ! -d ${backup_dir}/ograc/ograc_scripts ];then
        echo "Error: dir ${backup_dir}/ograc/ograc_scripts does not exist"
        return 1
    fi
    rm -rf ${ograc_scripts}/*
    cp -arf ${backup_dir}/ograc/ograc_scripts/* ${ograc_scripts}

    echo "rollback ograc local ${ograc_local}"
    if [ ! -d ${backup_dir}/ograc/ograc_local ];then
        echo "Error: dir ${backup_dir}/ograc/ograc_local does not exist"
        return 1
    fi
    rm -rf ${ograc_local}/*
    cp -arf ${backup_dir}/ograc/ograc_local/* ${ograc_local}

    echo "check that all files are rolled back to ensure that no data is lost for safety rollback"
    check_rollback_files ${backup_dir}/ograc/ograc_home_files_list.txt ${backup_dir}/ograc/ograc_home ${ograc_home}
    check_rollback_files ${backup_dir}/ograc/ograc_scripts_files_list.txt ${backup_dir}/ograc/ograc_scripts ${ograc_scripts}
    check_rollback_files ${backup_dir}/ograc/ograc_local_files_list.txt ${backup_dir}/ograc/ograc_local ${ograc_local}

    echo "======================== rollback ograc module successfully ========================"
    set +e
    return 0
}

deploy_user=$(cat ${CURRENT_PATH}/../../config/deploy_param.json |
              awk -F ',' '{for(i=1;i<=NF;i++){if($i~"deploy_user"){print $i}}}' |
              sed 's/ //g' | sed 's/:/=/1' | sed 's/"//g' |
              awk -F '=' '{print $2}')
d_user=$(echo ${deploy_user} | awk -F ':' '{print $2}')
node_id=$(cat ${CURRENT_PATH}/../../config/deploy_param.json |
              awk -F ',' '{for(i=1;i<=NF;i++){if($i~"node_id"){print $i}}}' |
              sed 's/ //g' | sed 's/:/=/1' | sed 's/"//g' |
              awk -F '=' '{print $2}')

user=$(echo ${ograc_user} | awk -F ':' '{print $2}')
owner=$(stat -c %U ${CURRENT_PATH})

function chown_mod_scripts() {
    set -e
    current_path_reg=$(echo $CURRENT_PATH | sed 's/\//\\\//g')
    scripts=$(ls ${CURRENT_PATH} | awk '{if($1!="appctl.sh"){print $1}}' | awk '{if($1!="ogracd_cgroup_calculate.sh"){print $1}}' |
            sed "s/^/${current_path_reg}\//")
    chown ${ograc_user} -h ${scripts}
    chmod 400 ${CURRENT_PATH}/*.sh ${CURRENT_PATH}/*.py
    chmod 600 ${CURRENT_PATH}/*.json
    set +e
}

function copy_ograc_scripts()
{
    if [ -d ${ograc_scripts} ]; then
        rm -rf ${ograc_scripts}
    fi
    mkdir -m 700 -p ${ograc_scripts}
    chown -h ${ograc_user} ${ograc_scripts}
    cp -arf ${CURRENT_PATH}/* ${ograc_scripts}/
}

function init_cpu_config()
{
    python3 ${CURRENT_PATH}/bind_cpu_config.py 'init_config'
}

function clean_ograc_scripts()
{
    if [ -d ${ograc_scripts} ]; then
        rm -rf ${ograc_scripts}
    fi
}

function check_old_install()
{
    if [ -d ${ograc_home}/server ]; then
        echo "Error: ograc has been installed in ${ograc_home}"
        exit 1
    fi

    #解决root包卸载残留问题
    chown ${ograc_user} -hR ${ograc_home}
    chmod 750 -R ${ograc_home}

    chown ${ograc_user} -hR ${ograc_log}
    chmod 750 -R ${ograc_log}
    find ${ograc_log} -type f -print0 | xargs -0 chmod 640

    #解决root包卸载残留问题
    ograc_local_owner=$(stat -c %U ${ograc_local})
    if [ ${ograc_local_owner} != ${user} ];then
        chown ${ograc_user} -hR ${ograc_local}
        chmod 750 -R ${ograc_local}/..
    fi
}

function check_and_create_ograc_home()
{
    if [ ! -d ${ograc_home} ]; then
        mkdir -m 750 -p ${ograc_home}
        chown ${ograc_user} -hR ${ograc_home}
    fi

    if [ ! -d ${ograc_log} ]; then
        mkdir -m 750 -p ${ograc_log}
        chown ${ograc_user} -hR ${ograc_log}
    fi

    if [ ! -d ${ograc_home}/cfg ]; then
        mkdir -m 700 -p ${ograc_home}/cfg
        chown ${ograc_user} -hR ${ograc_home}/cfg
    fi

    if [ ! -f ${LOG_FILE} ]; then
        touch ${LOG_FILE}
        chmod 640 ${LOG_FILE}
        chown ${ograc_user} -hR /opt/ograc/log > /dev/null 2>&1
    fi

    if [ ! -d ${ograc_local} ]; then
        mkdir -m 750 -p ${ograc_local}
        chown ${ograc_user} -hR ${ograc_local}
    fi

}

function update_cpu_config() {
    su -s /bin/bash - "${user}" -c "python3 ${CURRENT_PATH}/bind_cpu_config.py"
}

check_and_create_ograc_home

##################################### main #####################################
ACTION=$1
if [ $# -gt 1 ]; then
    INSTALL_TYPE=$2
    UNINSTALL_TYPE=$2
    BACKUP_UPGRADE_PATH=$2
    UPGRADE_TYPE=$2
    ROLLBACK_TYPE=$2
fi
if [ $# -gt 2 ]; then
    FORCE_UNINSTALL=$3
    BACKUP_UPGRADE_PATH=$3
fi

function main_deploy() {
    case "$ACTION" in
        start)
            create_cgroup_path
            update_cpu_config
            do_deploy ${START_NAME} ${INSTALL_TYPE}
            if [[ $? -ne 0 ]]; then
                exit 1
            fi
            exit $?
            ;;
        stop)
            do_deploy ${STOP_NAME}
            exit $?
            ;;
        pre_install)
            check_old_install
            chown_mod_scripts
            init_cpu_config
            do_deploy ${PRE_INSTALL_NAME} ${INSTALL_TYPE}
            exit $?
            ;;
        install)
            copy_ograc_scripts
            do_deploy ${INSTALL_NAME} ${INSTALL_TYPE}
            exit $?
            ;;
        init_container)
            do_deploy ${INIT_CONTAINER_NAME}
            exit $?
            ;;
        uninstall)
            do_deploy ${UNINSTALL_NAME} ${UNINSTALL_TYPE} ${FORCE_UNINSTALL}
            if [[ $? -ne 0 ]]; then
                exit 1
            fi
            cgroup_clean
            exit $?
            ;;
        check_status)
            do_deploy ${STATUS_NAME}
            exit $?
            ;;
        backup)
            do_deploy ${BACKUP_NAME}
            exit $?
            ;;
        restore)
            do_deploy ${RESTORE_NAME}
            exit $?
            ;;
        pre_upgrade)
            version_first_number=$(cat /opt/ograc/versions.yml |sed 's/ //g' | grep 'Version:' | awk -F ':' '{print $2}' | awk -F '.' '{print $1}')
            chown_mod_scripts
            pre_upgrade
            exit $?
            ;;
        upgrade_backup)
            version_first_number=$(cat /opt/ograc/versions.yml |sed 's/ //g' | grep 'Version:' | awk -F ':' '{print $2}' | awk -F '.' '{print $1}')
            safety_upgrade_backup ${BACKUP_UPGRADE_PATH}
            exit $?
            ;;
        upgrade)
            safety_upgrade ${UPGRADE_TYPE} ${BACKUP_UPGRADE_PATH}
            exit $?
            ;;
        rollback)
            safety_rollback ${ROLLBACK_TYPE} ${BACKUP_UPGRADE_PATH}
            exit $?
            ;;
        post_upgrade)
            post_upgrade
            exit $?
            ;;
        *)
            usage
            ;;
    esac
}

main_deploy &>> ${LOG_FILE}