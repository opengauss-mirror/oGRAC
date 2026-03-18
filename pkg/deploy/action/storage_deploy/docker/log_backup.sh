CURRENT_PATH=$(dirname $(readlink -f $0))
source ${CURRENT_PATH}/../log4sh.sh
if [[ $# -ne 5 ]] && [[ $# -ne 4 ]];then
    logAndEchoError "Usage: Please input 4 or 5 params: cluster_name cluster_id node_id deploy_user [storage_metadata_fs]"
    exit 1
fi
cluster_name=$1
cluster_id=$2
node_id=$3
deploy_user=$4
storage_metadata_fs=$5

function delete_log_if_too_much() {
    local dir_path="$1"
    local max_logs=20 #最大文件限制
    if [ ! -d "${dir_path}" ];then
        logAndEchoError "invalid log dir_path: ${dir_path}"
        exit 1
    fi
    local dirs=$(find ${dir_path} -type d -name "????-??-??-??-??-??*")
    local log_count=$(echo "${dirs}" | wc -l)
    
    if [ "${log_count}" -gt "${max_logs}" ]; then
        logAndEchoInfo "logs more than ${max_logs}, begin to delete oldest log"
        local sorted_dirs=$(echo "${dirs}" | sort)
        local oldest_dir=$(echo "${sorted_dirs}" | head -n 1)
        if [ -n "${oldest_dir}" ]; then
            rm -rf "$oldest_dir"
            logAndEchoInfo "found oldest log: ${oldest_dir}, remove complete"
        fi
    fi
}

function check_path_and_copy() {
    #获取参数
    src_path="$1"
    dst_path="$2"
    #检查是否存在
    if [ -e "${src_path}" ];then
        cp -rf ${src_path} ${dst_path}
    fi
}

function main() {
    logAndEchoInfo "Backup log begin."
    DATE=$(date +"%Y-%m-%d-%H-%M-%S")
    mkdir -p /home/mfdb_core/${cluster_name}_${cluster_id}/${DATE}-node${node_id}
    delete_log_if_too_much /home/mfdb_core/${cluster_name}_${cluster_id}
    cd /home/mfdb_core/${cluster_name}_${cluster_id}/${DATE}-node${node_id}
    mkdir ograc cms dbstor core_symbol
    mkdir ograc/opt ograc/mnt
    mkdir dbstor/opt dbstor/mnt dbstor/ftds dbstor/install
    check_path_and_copy /mnt/dbdata/local/ograc/tmp/data/log ograc/mnt
    check_path_and_copy /mnt/dbdata/local/ograc/tmp/data/cfg ograc/mnt
    check_path_and_copy /opt/ograc/log/ograc ograc/opt
    check_path_and_copy /opt/ograc/log/deploy ograc/opt
    check_path_and_copy /opt/ograc/ograc_exporter ograc/opt
    check_path_and_copy /opt/ograc/common/config ograc/opt
    check_path_and_copy /opt/ograc/log/cms cms/
    check_path_and_copy /opt/ograc/log/dbstor dbstor/mnt
    check_path_and_copy /opt/ograc/cms/dbstor/data/logs dbstor/opt
    check_path_and_copy /opt/ograc/dbstor/data/logs dbstor/install
    check_path_and_copy /mnt/dbdata/local/ograc/tmp/data/dbstor/data/ftds/ftds/data/stat dbstor/ftds
    check_path_and_copy /opt/ograc/ograc/server/bin core_symbol/
    logAndEchoInfo "Backup log complete."
}

main

