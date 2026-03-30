#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
CONFIG_PATH="/mnt/dbdata/local/ograc/tmp/data/cfg"
DORADO_CONF_PATH="${CURRENT_PATH}/../../config/container_conf/dorado_conf"
INIT_CONFIG_PATH="${CURRENT_PATH}/../../config/container_conf/init_conf"
SYS_PASS="sysPass"
CERT_PASS="certPass"
OGRAC_INSTALL_LOG_FILE="/opt/ograc/log/ograc/ograc_deploy.log"
OGRAC_CONFIG_NAME="ogracd.ini"
CLUSTER_CONFIG_NAME="cluster.ini"
OGSQL_CONFIG_NAME="ogsql.ini"
OGRAC_PARAM=("CPU_GROUP_INFO" "LARGE_POOL_SIZE" "CR_POOL_COUNT" "CR_POOL_SIZE" "TEMP_POOL_NUM" "BUF_POOL_NUM" \
                "LOG_BUFFER_SIZE" "LOG_BUFFER_COUNT" "SHARED_POOL_SIZE" "DATA_BUFFER_SIZE" "TEMP_BUFFER_SIZE" \
                "SESSIONS" "VARIANT_MEMORY_AREA_SIZE" \
                "DTC_RCY_PARAL_BUF_LIST_SIZE")

node_id=`python3 ${CURRENT_PATH}/get_config_info.py "node_id"`
ograc_user=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_user"`
archive_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_archive_fs"`
cluster_id=`python3 ${CURRENT_PATH}/get_config_info.py "cluster_id"`
deploy_mode=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_mode"`
storage_dbstor_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_dbstor_fs"`
cluster_name=`python3 ${CURRENT_PATH}/get_config_info.py "cluster_name"`
max_arch_files_size=`python3 ${CURRENT_PATH}/get_config_info.py "MAX_ARCH_FILES_SIZE"`
cms_ip=`python3 ${CURRENT_PATH}/get_config_info.py "cms_ip"`
mes_ssl_switch=`python3 ${CURRENT_PATH}/get_config_info.py "mes_ssl_switch"`
storage_metadata_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_metadata_fs"`
primary_keystore="/opt/ograc/common/config/primary_keystore_bak.ks"
standby_keystore="/opt/ograc/common/config/standby_keystore_bak.ks"
OGRAC_INSTALL_LOG_FILE=/opt/ograc/log/ograc/ograc_deploy.log

function log() {
  printf "[%s] %s\n" "`date -d today \"+%Y-%m-%d %H:%M:%S\"`" "$1" >> ${OGRAC_INSTALL_LOG_FILE}
}

function set_ogsql_config() {
    sys_password=`cat ${DORADO_CONF_PATH}/${SYS_PASS}`
    sed -i -r "s:(SYS_PASSWORD = ).*:\1${sys_password}:g" ${CONFIG_PATH}/${OGSQL_CONFIG_NAME}
}

# 清除信号量
function clear_sem_id() {
    signal_num="0x20161227"
    sem_id=$(lsipc -s -c | grep ${signal_num} | grep -v grep | awk '{print $2}')
    if [ -n "${sem_id}" ]; then
        ipcrm -s ${sem_id}
        if [ $? -ne 0 ]; then
            log "clear sem_id failed"
            exit 1
        fi
        log "clear sem_id success"
    fi
}

function set_ograc_config() {
    tmp_path=${LD_LIBRARY_PATH}
    export LD_LIBRARY_PATH=/opt/ograc/dbstor/lib:${LD_LIBRARY_PATH}
    password_tmp=`python3 -B "${CURRENT_PATH}"/../docker/resolve_pwd.py "kmc_to_ogencrypt_pwd" "${sys_password}"`
    export LD_LIBRARY_PATH=${tmp_path}
    clear_sem_id
    # 去除多余空格
    password=`eval echo ${password_tmp}`
    if [ -z "${password}" ]; then
        echo "failed to get _SYS_PASSWORD by ogencrypt" >> ${OGRAC_INSTALL_LOG_FILE}
        exit 1
    fi
    
    node_domain_0=`echo ${cms_ip} | awk '{split($1,arr,";");print arr[1]}'`
    node_domain_1=`echo ${cms_ip} | awk '{split($1,arr,";");print arr[2]}'`
    if [ -z "${node_domain_1}" ]; then
        node_domain_1="127.0.0.1"
    fi

    if [[ "$deploy_mode" == "dbstor" ]]; then
        sed -i -r "s:(ARCHIVE_DEST_1 = location=).*:\1\/${archive_fs}\/archive:g" ${CONFIG_PATH}/${OGRAC_CONFIG_NAME}
        sed -i -r "s/(DBSTOR_DEPLOY_MODE = ).*/\11/" ${CONFIG_PATH}/${OGRAC_CONFIG_NAME}
    else
        sed -i -r "s:(ARCHIVE_DEST_1 = location=/mnt/dbdata/remote/archive_).*:\1${archive_fs}:g" \
            ${CONFIG_PATH}/${OGRAC_CONFIG_NAME}
    fi

     if [[ "$deploy_mode" == "dbstor" || "$deploy_mode" == "combined" ]]; then
        sed -i -r "s/(ENABLE_DBSTOR = ).*/\1TRUE/" ${CONFIG_PATH}/${OGRAC_CONFIG_NAME}
    elif [[ "$deploy_mode" == "file" ]]; then
        sed -i -r "s/(ENABLE_DBSTOR = ).*/\1FALSE/" ${CONFIG_PATH}/${OGRAC_CONFIG_NAME}
        sed -i -r "s/(INTERCONNECT_TYPE = ).*/\1TCP/" ${CONFIG_PATH}/${OGRAC_CONFIG_NAME}
        sed -i "s|SHARED_PATH.*|SHARED_PATH = /mnt/dbdata/remote/storage_${storage_dbstor_fs}/data|g" ${CONFIG_PATH}/${OGRAC_CONFIG_NAME}
    else
        echo "Unknown deployment mode: $deploy_mode"
        exit 1
    fi

    sed -i -r "s:(INTERCONNECT_ADDR = ).*:\1${node_domain_0};${node_domain_1}:g" ${CONFIG_PATH}/${OGRAC_CONFIG_NAME}
    sed -i -r "s:(DBSTOR_NAMESPACE = ).*:\1${cluster_name}:g" ${CONFIG_PATH}/${OGRAC_CONFIG_NAME}
    sed -i -r "s:(INSTANCE_ID = ).*:\1${node_id}:g" ${CONFIG_PATH}/${OGRAC_CONFIG_NAME}
    sed -i -r "s:(NODE_ID = ).*:\1${node_id}:g" ${CONFIG_PATH}/${CLUSTER_CONFIG_NAME}
    sed -i -r "s:(MAX_ARCH_FILES_SIZE = ).*:\1${max_arch_files_size}:g" ${CONFIG_PATH}/${OGRAC_CONFIG_NAME}
    sed -i -r "s:(CLUSTER_ID = ).*:\1${cluster_id}:g" ${CONFIG_PATH}/${OGRAC_CONFIG_NAME}
    sed -i -r "s:(_SYS_PASSWORD = ).*:\1${password}:g" ${CONFIG_PATH}/${OGRAC_CONFIG_NAME}
    if [ ${node_id} == 0 ]; then
        sed -i -r "s:(LSNR_ADDR = ).*:\1127.0.0.1,${node_domain_0}:g" ${CONFIG_PATH}/${OGRAC_CONFIG_NAME}
    else
        sed -i -r "s:(LSNR_ADDR = ).*:\1127.0.0.1,${node_domain_1}:g" ${CONFIG_PATH}/${OGRAC_CONFIG_NAME}
    fi

    if [[ ${mes_ssl_switch} == "True" ]]; then
        cert_password=`cat ${DORADO_CONF_PATH}/${CERT_PASS}`
        sed -i -r "s:(MES_SSL_KEY_PWD = ).*:\1${cert_password}:g" ${CONFIG_PATH}/${OGRAC_CONFIG_NAME}
    else
        sed -i -r "s:(MES_SSL_SWITCH = ).*:\1FALSE:g" ${CONFIG_PATH}/${OGRAC_CONFIG_NAME}
    fi

    # 获取所有NUMA NODE的ID
    nodes=$(ls /sys/devices/system/node/ | grep -E 'node[0-9]+')

    # 遍历每个NUMA NODE，获取对应的CPU数据
    cpus=""
    for node in ${nodes}
    do
        cpu_list=$(cat /sys/devices/system/node/${node}/cpulist)
        cpus="${cpus} ${cpu_list}"
    done
    sed -i -r "s:(CPU_GROUP_INFO = ).*:\1${cpus}:g" ${CONFIG_PATH}/${OGRAC_CONFIG_NAME}
}

function set_ograc_param() {
    if [ -f ${INIT_CONFIG_PATH}/start_config.json ] || [ -f ${INIT_CONFIG_PATH}/mem_spec ]; then
        for param_name in "${OGRAC_PARAM[@]}"
        do
            param_value=`python3 ${CURRENT_PATH}/get_config_info.py ${param_name}`
            if [ ! -z ${param_value} ] && [ ${param_value} != "None" ]; then
                sed -i -r "s:(${param_name} = ).*:\1${param_value}:g" ${CONFIG_PATH}/${OGRAC_CONFIG_NAME}
                if ! grep -q "${param_name}" ${CONFIG_PATH}/${OGRAC_CONFIG_NAME};then
                  echo "${param_name} = ${param_value}" >> ${CONFIG_PATH}/${OGRAC_CONFIG_NAME}
                fi
            fi
        done
    fi
}

set_ogsql_config
set_ograc_config
set_ograc_param