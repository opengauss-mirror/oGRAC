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

"""DSS upgrade YAML file management."""

import os
import sys
import traceback

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CUR_DIR)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

from log_config import get_logger
from common.dss_cmd import vg_rm, vg_cp, vg_find_matching_files
from common.file_utils import pad_file_to_512

LOG = get_logger()


class DssYaml:
    def __init__(self):
        self.file_name = None
        self.local_path = None
        self.vg_path = None

    def _remove_existing(self):
        """Remove existing file in VG if same name exists."""
        matches = vg_find_matching_files("+vg1", self.file_name)
        if matches:
            vg_rm(self.vg_path)

    def upload(self, input_file):
        """Upload YAML file to VG (aligned to 512 bytes)."""
        self.file_name = os.path.basename(input_file)
        self.local_path = input_file
        self.vg_path = os.path.join("+vg1", self.file_name)

        pad_file_to_512(self.local_path)
        self._remove_existing()
        vg_cp(self.local_path, self.vg_path)
        LOG.info(f"YAML uploaded: {self.file_name}")


def main():
    if len(sys.argv) < 2:
        raise RuntimeError("Usage: dss_upgrade_yaml.py <yaml_file>")
    try:
        DssYaml().upload(sys.argv[1])
    except Exception as e:
        LOG.error(f"Failed to upload YAML: {traceback.format_exc(limit=-1)}")
        raise


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        sys.exit(str(err))
