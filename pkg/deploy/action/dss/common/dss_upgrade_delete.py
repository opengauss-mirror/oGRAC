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

"""DSS upgrade file deletion."""

import os
import sys
import traceback

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CUR_DIR)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

from log_config import get_logger
from common.dss_cmd import (
    vg_rm, vg_rmdir, vg_file_exists, vg_find_matching_files,
)

LOG = get_logger()

UPGRADE_VG_PATH = "+vg1/upgrade"
STATUS_VG_PATH = "+vg1/upgrade/cluster_and_node_status"


class DssDelete:
    """Upgrade-related file deletion."""

    @staticmethod
    def _delete_matching(keyword, vg_path):
        """Delete files matching keyword in directory."""
        matches = vg_find_matching_files(vg_path, keyword)
        for fname in matches:
            vg_rm(f"{vg_path}/{fname}")
            LOG.info(f"Deleted: {vg_path}/{fname}")

    @staticmethod
    def _delete_node_status_files():
        """Delete nodeX_status.txt files."""
        matches = vg_find_matching_files(STATUS_VG_PATH, "node")
        for fname in matches:
            if "status.txt" in fname:
                vg_rm(f"{STATUS_VG_PATH}/{fname}")
                LOG.info(f"Deleted: {STATUS_VG_PATH}/{fname}")

    def delete(self, input_file):
        """Delete by file type."""
        if "updatesys" in input_file:
            self._delete_matching("updatesys", UPGRADE_VG_PATH)

        elif input_file == "cluster_and_node_status":
            vg_rmdir(STATUS_VG_PATH)
            LOG.info(f"Deleted directory: {STATUS_VG_PATH}")

        elif "cluster_and_node_status/node" in input_file:
            self._delete_node_status_files()

        elif "upgrade_node" in input_file:
            self._delete_matching("upgrade_node", UPGRADE_VG_PATH)

        else:
            if not vg_file_exists(f"{UPGRADE_VG_PATH}/{input_file}"):
                return
            vg_rm(f"{UPGRADE_VG_PATH}/{input_file}")
            LOG.info(f"Deleted: {UPGRADE_VG_PATH}/{input_file}")


def main():
    if len(sys.argv) < 2:
        raise RuntimeError("Usage: dss_upgrade_delete.py <file>")
    try:
        DssDelete().delete(sys.argv[1])
    except Exception as e:
        LOG.error(f"Failed to delete: {traceback.format_exc(limit=-1)}")
        raise


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        sys.exit(str(err))
