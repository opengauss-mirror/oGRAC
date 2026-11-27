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
# This script is used for compiling code via CMake and making packages
set -e

BEPKIT_HOME=/opt/buildtools/sepCloud/Bep_Env_For_Linux

${BEPKIT_HOME}/bep_env.sh -i
ldconfig
cp -r ${BEPKIT_HOME}/bep_env.conf  /home/
source ${BEPKIT_HOME}/bep_env.sh -s /home/bep_env.conf

sh Makefile.sh package-release