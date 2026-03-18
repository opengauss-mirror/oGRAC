#!/usr/bin/env python3
"""DSS upgrade unlock."""

import os
import sys
import traceback

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CUR_DIR)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

from log_config import get_logger
from common.dss_cmd import vg_rm, vg_find_matching_files

LOG = get_logger()

UPGRADE_VG_PATH = "+vg1/upgrade"


class DssUnlock:
    def __init__(self):
        self.lock_file_name = None
        self.vg_lock_path = None

    def _is_locked(self):
        matches = vg_find_matching_files(UPGRADE_VG_PATH, self.lock_file_name)
        return len(matches) > 0

    def unlock(self, input_file):
        """Release upgrade lock."""
        self.lock_file_name = os.path.basename(input_file)
        self.vg_lock_path = os.path.join(UPGRADE_VG_PATH, self.lock_file_name)

        if self._is_locked():
            vg_rm(self.vg_lock_path)
            LOG.info(f"Lock released: {self.lock_file_name}")


def main():
    if len(sys.argv) < 2:
        raise RuntimeError("Usage: dss_upgrade_unlock.py <lock_file>")
    try:
        DssUnlock().unlock(sys.argv[1])
    except Exception as e:
        LOG.error(f"Failed to unlock: {traceback.format_exc(limit=-1)}")
        raise


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        sys.exit(str(err))
