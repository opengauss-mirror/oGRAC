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
CURRENT_PATH=$(dirname $(readlink -f $0))
ld_path_src=${LD_LIBRARY_PATH}
export LD_LIBRARY_PATH=/opt/ograc/dbstor/lib:${LD_LIBRARY_PATH}
python3 "${CURRENT_PATH}"/dr_deploy.py
if [[ $? -ne 0 ]];then
  echo "executing dr_deploy failed."
  export LD_LIBRARY_PATH=${ld_path_src}
  exit 1
fi
export LD_LIBRARY_PATH=${ld_path_src}