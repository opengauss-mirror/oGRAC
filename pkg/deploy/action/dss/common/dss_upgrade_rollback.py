#!/usr/bin/env python3
"""DSS upgrade rollback check."""

import os
import sys
import traceback

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CUR_DIR)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

from log_config import get_logger
from common.dss_cmd import vg_list_files
from common.file_utils import read_dss_file

LOG = get_logger()

UPGRADE_VG_PATH = "+vg1/upgrade"
STATUS_VG_PATH = "+vg1/upgrade/cluster_and_node_status"


class DssRollbackChecker:
    """Check if offline rollback can be executed."""

    def _check_file_content(self, file_name):
        """Check if status file content is 'commit'."""
        vg_path = os.path.join(STATUS_VG_PATH, file_name)
        content = read_dss_file(vg_path)
        if content != "commit":
            raise RuntimeError(
                f"Rolling upgrade in progress, offline rollback blocked by {file_name}"
            )

    def _check_vg_directory(self, path):
        """Check upgrade status in VG directory."""
        lines = vg_list_files(path)
        if lines is None or len(lines) == 0:
            return

        for line in lines:
            if "written_size" in line:
                continue
            parts = line.strip().split()
            file_name = parts[5] if len(parts) >= 6 else parts[-1] if parts else ""

            if "updatesys.success" in line or "updatesys.failed" in line:
                raise RuntimeError(
                    f"Rolling upgrade in progress, offline rollback blocked by {file_name}"
                )
            if "cluster_status.txt" in line:
                self._check_file_content(file_name)

    def check(self):
        """Execute rollback check."""
        self._check_vg_directory(UPGRADE_VG_PATH)
        self._check_vg_directory(STATUS_VG_PATH)
        LOG.info("Rollback pre-check passed")


def main():
    try:
        DssRollbackChecker().check()
    except Exception as e:
        LOG.error(f"Rollback check failed: {traceback.format_exc(limit=-1)}")
        raise


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        sys.exit(str(err))
