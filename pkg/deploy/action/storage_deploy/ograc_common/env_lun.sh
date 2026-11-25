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
CURRENT_FILE_PATH=$(dirname $(readlink -f $0))
INSTALL_PATH=/opt/ograc
BACKUP_PATH=/opt/ograc/backup
NFS_PORT=36729

ograc_user="ograc"
ograc_group="ograc"
ograc_common_group="ogracgroup"

PRE_INSTALL_ORDER=("ograc" "cms" "dss")
INSTALL_ORDER=("cms" "dss" "ograc" "og_om" "ograc_exporter")
START_ORDER=("cms" "dss" "ograc" "og_om" "ograc_exporter")
STOP_ORDER=("cms" "dss" "ograc" "og_om" "ograc_exporter")
UNINSTALL_ORDER=("og_om" "ograc" "dss" "cms")
BACKUP_ORDER=("ograc" "dss" "cms" "og_om")
CHECK_STATUS=("ograc" "cms" "dss" "og_om" "ograc_exporter")
PRE_UPGRADE_ORDER=("og_om" "ograc_exporter" "cms" "ograc")
UPGRADE_ORDER=("og_om" "ograc_exporter" "cms" "ograc")
POST_UPGRADE_ORDER=("og_om" "ograc_exporter" "cms" "ograc")
ROLLBACK_ORDER=("cms" "ograc" "og_om" "ograc_exporter")
INIT_CONTAINER_ORDER=("cms" "ograc")
DIR_LIST=(/opt/ograc/cms  /opt/ograc/ograc /opt/ograc/dbstor ${CURRENT_FILE_PATH}/inspection/inspection_scripts/kernal ${CURRENT_FILE_PATH}/inspection/inspection_scripts/cms ${CURRENT_FILE_PATH}/inspection/inspection_scripts/og_om)