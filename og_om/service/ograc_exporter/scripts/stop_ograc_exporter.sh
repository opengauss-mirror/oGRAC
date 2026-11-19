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
OM_DEPLOY_LOG_FILE=/opt/ograc/log/ograc_exporter/ograc_exporter.log

function log() {
  printf "[%s] %s\n" "`date -d today \"+%Y-%m-%d %H:%M:%S\"`" "$1" >> ${OM_DEPLOY_LOG_FILE} 2>&1
}

function check_python_script_status() {
    py_pid=$(ps -ef | grep "python3 /opt/ograc/og_om/service/ograc_exporter/exporter/execute.py" | grep -v grep | awk '{print $2}')
    if [ -z "${py_pid}" ];then
        return 1
    fi
    return 0
}

# 杀死父进程派生的子孙进程
function kill_descendants() {
    local parent_pid=$1

    # 获取所有子孙进程的PID
    descendants=$(pgrep -P "$parent_pid")

    # 杀掉子孙进程
    for pid in ${descendants[@]}; do
        kill_descendants "${pid}"  # 递归杀掉子孙进程
    done

    kill -9 "${parent_pid}"
}

function kill_python_script_process() {
    check_python_script_status
    if [ $? -eq 0 ];then
        og_exporter_pid=$(ps -ef | grep "python3 /opt/ograc/og_om/service/ograc_exporter/exporter/execute.py" | grep -v grep | awk '{print $2}')
        kill_descendants "${og_exporter_pid}"
        if [ $? -eq 0 ];then
            log "Success to kill [execute.py] process"
        else
            log "Fail to kill [execute.py] process"
            exit 1
        fi
    else
        log "Python scripts process [execute.py] does not exist, no need to kill"
    fi
}

log "Start to kill ograc_exporter daemon and python scripts process"

kill_python_script_process

log  "Success to execute current shell script"
