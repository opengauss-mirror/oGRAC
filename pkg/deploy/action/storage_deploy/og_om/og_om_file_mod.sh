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

# OGOM_BASIC_FILE_MODE_MAP会覆盖OGOM_FILE_R_MODE_MAP设置的权限，OGOM_FILE_R_MODE_MAP会覆盖OGOM_FILE_MODE_MAP的权限
declare -A OGOM_BASIC_FILE_MODE_MAP  # 基础权限配置map，最先运行
declare -A OGOM_FILE_R_MODE_MAP # 递归权限配置map，其次运行
declare -A OGOM_FILE_MODE_MAP # 单独路径、文件配置map，最后运行

OGOM_BASIC_FILE_MODE_MAP["${CURRENT_PATH}"]="400"

OGOM_FILE_MODE_MAP["${CURRENT_PATH}"]="755"