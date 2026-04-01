#!/usr/bin/env python3
"""DSS upgrade lock management."""

import os
import sys
import traceback

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CUR_DIR)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

from log_config import get_logger
from common.dss_cmd import vg_mkdir, vg_touch, vg_list_files, vg_find_matching_files

LOG = get_logger()

UPGRADE_VG_PATH = "+vg1/upgrade"


class DssLock:
    def __init__(self):
        self.lock_file_name = None
        self.vg_lock_path = None
        self.lock_status = None

    def _check_lock_status(self):
        """Check upgrade lock status."""
        lines = vg_list_files(UPGRADE_VG_PATH)

        if lines is None:
            self.lock_status = "upgrade_not_exists"
            return

        if len(lines) == 0:
            self.lock_status = "upgrade_empty"
            return

        for line in lines:
            if self.lock_file_name in line:
                self.lock_status = "already_locked"
                return
            if "upgrade_lock_" in line:
                raise RuntimeError(f"Other lock is in use: {line}")

        self.lock_status = "not_locked"

    def lock(self, input_file):
        """Acquire upgrade lock."""
        self.lock_file_name = os.path.basename(input_file)
        self.vg_lock_path = os.path.join(UPGRADE_VG_PATH, self.lock_file_name)

        self._check_lock_status()

        if self.lock_status == "upgrade_not_exists":
            vg_mkdir("+vg1", "upgrade")
        elif self.lock_status == "already_locked":
            return

        vg_touch(self.vg_lock_path)
        LOG.info(f"Lock acquired: {self.lock_file_name}")


def main():
    if len(sys.argv) < 2:
        raise RuntimeError("Usage: dss_upgrade_lock.py <lock_file>")
    try:
        DssLock().lock(sys.argv[1])
    except Exception as e:
        LOG.error(f"Failed to lock: {traceback.format_exc(limit=-1)}")
        raise


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        sys.exit(str(err))
