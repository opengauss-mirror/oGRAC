#!/usr/bin/env python3
import sys
import os
import re
from pathlib import Path

CUR_PATH = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, CUR_PATH)

from config import get_config, get_value

_cfg = get_config()
_paths = _cfg.paths

sys.path.append(os.path.join(CUR_PATH, ".."))
from om_log import LOGGER as LOG

METADATA_FS = get_value("storage_metadata_fs")
VERSION_PREFIX = 'Version:'
SUB_VERSION_PREFIX = ('B', 'SP')


class UpgradeVersionCheck:

    def __init__(self):
        self.white_list_file = str(Path(os.path.join(CUR_PATH, "white_list.txt")))
        metadata_path = _paths.metadata_fs_path(METADATA_FS)
        self.source_version_file = str(Path(os.path.join(metadata_path, "versions.yml")))
        self.white_list_dict = {}
        self.source_version = ''
        self.err = {'read_failed': 'white list or source version read failed',
                    'match_failed': 'source version not in white list',
                    'updata_system_version_failed': 'update system version failed'}

    @staticmethod
    def update_system_version():
        """Reserved interface for updating system version."""
        return True

    @staticmethod
    def execption_handler(err_msg):
        LOG.error(err_msg)
        return 'False {}'.format(err_msg)

    def process_white_list(self):
        with open(self.white_list_file, 'r', encoding='utf-8') as file:
            white_list_info = file.readlines()

        for white_list_detail in white_list_info[1:]:
            if not white_list_detail.strip():
                continue
            details = white_list_detail.split()
            self.white_list_dict[details[0]] = [details[1], details[2]]

    def read_source_version_info(self):
        version = ''
        with open(self.source_version_file, 'r', encoding='utf-8') as file:
            source_version_info = file.readlines()

        for line in source_version_info:
            if VERSION_PREFIX in line:
                version = line.split()[-1]

        self.source_version = version

    def source_version_check(self):
        for white_list_version, white_list_detail in self.white_list_dict.items():
            *white_main_version, white_sub_version = white_list_version.split('.')
            *source_main_version, source_sub_version = self.source_version.split('.')
            if source_main_version != white_main_version:
                continue

            if white_sub_version == '*' or white_sub_version == source_sub_version:
                if "rollup" in white_list_detail[0]:
                    return 'True {} rollup'.format(white_list_detail[1])
                return 'True {} offline'.format(white_list_detail[1])

        err_msg = "source version '{}' not in white list.".format(self.source_version)
        return self.execption_handler(err_msg)


if __name__ == '__main__':
    version_check = UpgradeVersionCheck()
    version_check.read_source_version_info()
    version_check.process_white_list()
    print(version_check.source_version_check())
