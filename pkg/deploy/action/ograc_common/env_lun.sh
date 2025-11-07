#!/bin/bash
set +x
CURRENT_FILE_PATH=$(dirname $(readlink -f $0))
INSTALL_PATH=/opt/ograc
BACKUP_PATH=/opt/ograc/backup
NFS_PORT=36729

ograc_user="ograc"
ograc_group="ograc"
ograc_common_group="ogracgroup"

PRE_INSTALL_ORDER=("ograc" "cms" "dbstor" "dss")
INSTALL_ORDER=("dbstor" "cms" "dss" "ograc" "og_om" "ograc_exporter")
START_ORDER=("cms" "dss" "ograc" "og_om" "ograc_exporter")
STOP_ORDER=("cms" "dss" "ograc" "og_om" "ograc_exporter")
UNINSTALL_ORDER=("og_om" "ograc" "dss" "cms" "dbstor")
BACKUP_ORDER=("ograc" "dss" "cms" "og_om" "dbstor" )
CHECK_STATUS=("ograc" "cms" "dss" "og_om" "ograc_exporter")
PRE_UPGRADE_ORDER=("og_om" "ograc_exporter" "dbstor" "cms" "dss" "ograc")
UPGRADE_ORDER=("og_om" "ograc_exporter" "dbstor" "cms" "dss" "ograc")
POST_UPGRADE_ORDER=("og_om" "ograc_exporter" "dbstor" "cms" "dss" "ograc")
ROLLBACK_ORDER=("dbstor" "cms" "ograc" "og_om" "ograc_exporter")
INIT_CONTAINER_ORDER=("dbstor" "cms" "ograc")
DIR_LIST=(/opt/ograc/cms  /opt/ograc/ograc /opt/ograc/dbstor ${CURRENT_FILE_PATH}/inspection/inspection_scripts/kernal ${CURRENT_FILE_PATH}/inspection/inspection_scripts/cms ${CURRENT_FILE_PATH}/inspection/inspection_scripts/og_om)