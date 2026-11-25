# Copyright (c) 2026 Huawei Technologies Co., Ltd.
# oGRAC is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

VG_CONFIG = {
    "vg1": "/dev/dss-disk1",
    "vg2": "/dev/dss-disk2",
    "vg3": "/dev/dss-disk3"
}

INST_CONFIG = {
    "INST_ID": 0,
    "_LOG_LEVEL": 7,
    "STORAGE_MODE": "CLUSTER_RAID",
    "DSS_NODES_LIST": "0:127.0.0.1:1811, 1:127.0.0.2:1811",
    "LSNR_PATH": "",
    "_LOG_BACKUP_FILE_COUNT": "40",
    "_LOG_MAX_FILE_SIZE": "120M",
    "DSS_CM_SO_NAME": "libdsslock.so"
}