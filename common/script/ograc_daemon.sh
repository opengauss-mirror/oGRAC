#!/bin/bash

# 检查cms进程和ograc_exportor进程是否在位

set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)
CMS_ENABLE_FLAG=/opt/ograc/cms/cfg/cms_enable
DEPLOY_USER=$(python3 "${CURRENT_PATH}"/../../action/get_config_info.py "deploy_user")
node_count=$(python3 ${CURRENT_PATH}/../../action/get_config_info.py "cluster_scale")
CMS_CGROUP=/sys/fs/cgroup/memory/cms
OGMGR_CGROUP=/sys/fs/cgroup/memory/ogmgr
OGRAC_EXPORTER_CGROUP=/sys/fs/cgroup/memory/ograc_exporter
OGRACD_CGROUP_CALCULATE=${CURRENT_PATH}/../../action/ograc/ogracd_cgroup_calculate.sh
CMS_MEM_LIMIT=95

source ${CURRENT_PATH}/log4sh.sh
source ${OGRACD_CGROUP_CALCULATE}
source "${CURRENT_PATH}"/../../action/env.sh

declare -A CGROUP_SIZE_MAP=(['cms']=10240 ['ograc_exporter']=2048 ['ogmgr']=2048 ['ogracd']=${DEFAULT_MEM_SIZE})

function create_cgroup() {
    local cgroup_path=$1

    if [ -d "${cgroup_path}" ]; then
        rmdir "${cgroup_path}"
    fi
    mkdir -p "${cgroup_path}"
    local cgroup_model_path_lis=($(echo ${cgroup_path} | tr '/' ' '))
    local cgroup_memory=${CGROUP_SIZE_MAP[${cgroup_model_path_lis[-1]}]}
    sh -c "echo ${cgroup_memory}M > ${cgroup_path}/memory.limit_in_bytes"
    if [ $? -eq 0 ]; then
        logAndEchoInfo "limited ${cgroup_model_path_lis[-1]} memory ${cgroup_memory} to ${cgroup_path}/memory.limit_in_bytes success"
    else
        logAndEchoError "limited ${cgroup_model_path_lis[-1]} memory ${cgroup_memory} to ${cgroup_path}/memory.limit_in_bytes failed"
    fi
}

function cgroup_add_pid() {
    procs_pid=$1
    cgroup=$2

    if [[ -n ${procs_pid} && -n ${cgroup} ]]; then
        cat ${cgroup}/tasks | grep ${procs_pid} > /dev/null 2>&1
        if [ $? -ne 0 ]; then  # 如果cgroup不存在或者cgroup中tasks中没有进程 进入判断
            create_cgroup ${cgroup}
            sh -c "echo ${procs_pid} > ${cgroup}/tasks"
            if [ $? -ne 0 ]; then
                logAndEchoError "add pid[${procs_pid}] to cgroup: ${cgroup} failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            else
                logAndEchoInfo "add pid[${procs_pid}] to cgroup: ${cgroup} success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            fi
        fi
    fi
}

function add_cpu_cgroup() {
    procs_pid=$1
    cgroup=$2
     if [[ -n ${procs_pid} && -n ${cgroup} ]]; then
        cat ${cgroup}/cgroup.procs | grep ${procs_pid} > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            sh -c "echo ${procs_pid} > ${cgroup}/cgroup.procs"
            if [ $? -ne 0 ]; then
                logAndEchoError "add pid to cgroup: ${cgroup} failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            else
                logAndEchoInfo "add pid to cgroup: ${cgroup} success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            fi
        fi
    fi

}

# 监控系统内存占用百分比
function system_memory_used_percent() {
    # 获取当前系统内存使用情况
    total_mem=$(free -m | grep Mem | awk '{print $2}')
    used_mem=$(free -m | grep Mem | awk '{print $3}')
    able_mem=$(free -m | grep Mem | awk '{print $7}')
    
    # 计算内存使用占比
    mem_usage=$(printf "%.2f" $(echo "scale=2; $used_mem / $total_mem * 100" | bc))
    mem_able=$(printf "%.2f" $(echo "scale=2; $able_mem / $total_mem * 100" | bc))
}

# 守护进程启动时，默认开启enable cms_reg
su -s /bin/bash - "${ograc_user}" -c "sh /opt/ograc/action/cms/cms_reg.sh enable"

# 循环间隔 0.8s
LOOP_TIME=0.8
# cms后台重拉计数，最大10次，避免cms start卡死后，后台进程过多导致节点资源耗尽
CMS_COUNT=0
while :
do
    cms_pid=`ps -ef | grep cms | grep server | grep start | grep -v grep | awk 'NR==1 {print $2}'`

    # 创建ograc_exporter cgroup
    ograc_exporter_pid=$(ps -ef | grep "python3 /opt/ograc/og_om/service/ograc_exporter/exporter/execute.py" | grep -v grep | awk 'NR==1 {print $2}')
    if [ -z ${ograc_exporter_pid} ];then
        logAndEchoInfo "[ograc daemon] ograc_exporter is check_status return 1, begin to start ograc_exporter. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        sh /opt/ograc/action/ograc_exporter/appctl.sh start
        logAndEchoInfo "[ograc daemon] start ograc_exporter result: $?. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    fi
    # 创建ogmgr cgroup
    ogmgr_pid=$(ps -ef | grep "python3 /opt/ograc/og_om/service/ogmgr/uds_server.py" | grep -v grep | awk ' NR==1 {print $2}')
    if [ -z ${ogmgr_pid} ];then
        logAndEchoInfo "[ograc daemon] og_om is check_status return 1, begin to start og_om. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        sh /opt/ograc/action/og_om/appctl.sh start
        logAndEchoInfo "[ograc daemon] start og_om result: $?. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    fi

    # CCB结论：内存阈值主动故障倒换
    system_memory_used_percent
    if [[ -n ${cms_pid} ]]; then
        if [[ $(echo "$mem_usage > ${CMS_MEM_LIMIT}" | bc) -eq 1 ]] || [[ $(echo "$mem_able < 100-${CMS_MEM_LIMIT}" | bc) -eq 1 ]]; then
            top5_processes=$(ps aux --sort=-%mem | awk 'NR<=6{print $11, $2, $6/1024/1024}' | awk 'NR>1{printf "%s %s %.2fGB ", $1, $2, $3}')
            logAndEchoError "[ograc daemon] The top5 processes that occupy the memory are as follows: ${top5_processes}."
            su -s /bin/bash - "${ograc_user}" -c "sh /opt/ograc/action/cms/cms_reg.sh disable"
            kill -9 ${cms_pid}
            logAndEchoError "[ograc daemon] CMS ABORT !!! cause system memory problem, Current usage: ${mem_usage}%, Current able: ${mem_able}%."
        fi
    fi
    
    if [ ! -f ${CMS_ENABLE_FLAG} ]; then
        sleep ${LOOP_TIME}
        continue
    fi

    cms_process_info=$(ps -fu ${ograc_user} | grep "cms server -start" | grep -vE '(grep|defunct)')
    if [ -z ${cms_process_info} ]; then
      cms_process_count=0
    else
      cms_process_count=$(echo "${cms_process_info}" | wc -l)
    fi
    if [ ${cms_process_count} -ne 1 ]; then
        if [ ${CMS_COUNT} -le 9 ]; then
            logAndEchoInfo "[ograc daemon] the process count of cms is ${cms_process_count}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            if [[ -n ${cms_process_info} ]]; then
                logAndEchoInfo "[ograc daemon] cms process info: ${cms_process_info} [Line:${LINENO}, File:${SCRIPT_NAME}]"
            fi

            logAndEchoInfo "[ograc daemon] cms status is abnormal. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            CMS_COUNT=$(expr "${CMS_COUNT}" + 1)
            if [ ${cms_process_count} -eq 0 ]; then
                iptables_path=$(whereis iptables | awk -F: '{print $2}')
                if [ ! -z "${iptables_path}" ];then
                    logAndEchoInfo "[ograc daemon] begin to close iptables. [Line:${LINENO}, File:${SCRIPT_NAME}]"
                    iptables -D INPUT -p tcp --sport 14587 -j ACCEPT -w 60
                    iptables -D FORWARD -p tcp --sport 14587 -j ACCEPT -w 60
                    iptables -D OUTPUT -p tcp --sport 14587 -j ACCEPT -w 60
                    iptables -I INPUT -p tcp --sport 14587 -j ACCEPT -w 60
                    iptables -I FORWARD -p tcp --sport 14587 -j ACCEPT -w 60
                    iptables -I OUTPUT -p tcp --sport 14587 -j ACCEPT -w 60
                fi
                logAndEchoInfo "[ograc daemon] begin to start cms use ${ograc_user}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
                su -s /bin/bash - ${ograc_user} -c "sh /opt/ograc/action/cms/cms_start2.sh -start" >> /opt/ograc/log/deploy/deploy_daemon.log 2>&1 &
                logAndEchoInfo "[ograc daemon] starting cms in backstage ${CMS_COUNT} times. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            fi
        fi
        sleep ${LOOP_TIME}
    else
        CMS_COUNT=0
    fi
    
    sleep ${LOOP_TIME}
done

