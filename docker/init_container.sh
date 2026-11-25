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

user=$1
core_dir=$2
commitID=$3

if [[ "${user}" == "root" ]]; then
    echo "Root has already created"
    exit 0
fi

useradd -m ${user} -u 5000
chown -R ${user}:${user} ${core_dir}
mkdir -p /home/regress/ograc_data/gcc_home /home/regress/ograc_data/data
chmod 755 /home/regress
chmod -R 777 /home/regress/ograc_data
chown -R ${user}:${user} /home/regress/ograc_data
# 只预建 logs：data/install 由安装时按 -D/-R 创建。不能预建——ogracd 经 "su -" 启动后
# cwd 为 /home/${user}，预建的 data/install 会使 CREATE DIRECTORY 相对路径检查误判存在，
# 导致 bison_parser_2 等回归用例失败
mkdir -p /home/${user}/logs
chown -R ${user}:${user} /home/${user}
rm -f /etc/maven/settings.xml
cp /home/regress/ogracKernel/CI/maven/settings.xml /etc/maven/settings.xml
sed -i '/source \/etc\/profile/d' /root/.bashrc
echo "source /etc/profile" >> /root/.bashrc
echo "alias ll='ls -alrt'" >> /etc/profile
echo "${user} ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers


