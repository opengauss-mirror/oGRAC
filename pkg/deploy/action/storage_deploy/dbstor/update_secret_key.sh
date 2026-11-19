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

CURRENT_PATH=$(dirname $(readlink -f $0))
KEY_TYPE=$1

ograc_user=$(python3 ${CURRENT_PATH}/../ograc/get_config_info.py "deploy_user")
current_user=$(whoami)

if [[ ${ograc_user} != ${current_user} ]]; then
    echo "please switch the current user to ${ograc_user}"
    exit 1
fi

local_path=$LD_LIBRARY_PATH
export LD_LIBRARY_PATH=/opt/ograc/dbstor/lib/:$LD_LIBRARY_PATH
python3 ${CURRENT_PATH}/kmc_adapter.py ${KEY_TYPE}
ret=$?
export LD_LIBRARY_PATH=$local_path
if [ "${ret}" != 0 ]; then
    echo "update key failed!"
    exit 1
fi