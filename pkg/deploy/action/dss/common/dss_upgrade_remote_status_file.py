#!/usr/bin/env python3
# Copyright (c) 2026 Huawei Technologies Co., Ltd.
# oGRAC is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

"""DSS upgrade remote status file management."""

import os
import sys
import traceback

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CUR_DIR)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

from log_config import get_logger
from common.dss_cmd import vg_file_exists, vg_rm, vg_cp, vg_mkdir
from common.file_utils import pad_file_to_512

LOG = get_logger()

UPGRADE_VG_PATH = "+vg1/upgrade"
STATUS_VG_PATH = "+vg1/upgrade/cluster_and_node_status"


class DssRemoteStatus:
    """Remote status file upload management."""

    @staticmethod
    def _upload_to_vg(local_path, vg_path):
        """Upload file to VG (remove then copy)."""
        if vg_file_exists(vg_path):
            vg_rm(vg_path)
        vg_cp(local_path, vg_path)

    def upload(self, remote_status_file):
        """Upload remote status file."""
        file_name = os.path.basename(remote_status_file)
        pad_file_to_512(remote_status_file)

        if "cluster_and_node_status" in remote_status_file:
            vg_path = os.path.join(STATUS_VG_PATH, file_name)
            if not vg_file_exists(STATUS_VG_PATH):
                vg_mkdir(UPGRADE_VG_PATH, "cluster_and_node_status")
        else:
            vg_path = os.path.join(UPGRADE_VG_PATH, file_name)

        self._upload_to_vg(remote_status_file, vg_path)
        LOG.info(f"Remote status uploaded: {file_name}")


def main():
    if len(sys.argv) < 2:
        raise RuntimeError("Usage: dss_upgrade_remote_status_file.py <file>")
    try:
        DssRemoteStatus().upload(sys.argv[1])
    except Exception as e:
        LOG.error(f"Failed to upload status: {traceback.format_exc(limit=-1)}")
        raise


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        sys.exit(str(err))
