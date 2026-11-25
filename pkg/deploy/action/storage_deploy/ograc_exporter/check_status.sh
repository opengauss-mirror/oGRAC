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

function check_python_script_status()
{
    py_pid=$(ps -ef | grep "python3 /opt/ograc/og_om/service/ograc_exporter/exporter/execute.py" | grep -v grep | awk '{print $2}')
    if [ -z "${py_pid}" ];then
        return 1
    fi
    return 0
}


function main()
{
    check_python_script_status
    return $?

}

main
