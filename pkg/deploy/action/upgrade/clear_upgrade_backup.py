#!/usr/bin/env python3
"""Clear upgrade backup files."""
import os
import copy
import sys

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
ACTION_DIR = os.path.dirname(CUR_DIR)
sys.path.insert(0, ACTION_DIR)

from log_config import get_logger
from config import get_config

LOG = get_logger("deploy")
cfg = get_config()

UPGRADE_BACKUP_DIR = cfg.paths.upgrade_backup_root
BACKUP_NOTE_FILE = "/opt/backup_note"


class BackupRemover:
    def __init__(self):
        self._all_backup_list = self._get_all_backup_list()
        self._current_backup_list = self._get_recently_backup()

    @staticmethod
    def _get_all_backup_list():
        try:
            items = os.listdir(UPGRADE_BACKUP_DIR)
        except FileNotFoundError:
            LOG.error("upgrade backup path not exist: %s", UPGRADE_BACKUP_DIR)
            sys.exit(1)
        except Exception as err:
            LOG.error("list dir %s failed: %s", UPGRADE_BACKUP_DIR, err)
            sys.exit(1)

        if not items:
            LOG.error("upgrade backup path is empty: %s", UPGRADE_BACKUP_DIR)
            sys.exit(1)
        return items

    @staticmethod
    def _get_recently_backup():
        if not os.path.exists(BACKUP_NOTE_FILE):
            LOG.error("backup note not exist: %s", BACKUP_NOTE_FILE)
            sys.exit(1)

        with open(BACKUP_NOTE_FILE, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f if line.strip()]

        result = []
        for line in lines:
            parts = line.split(':')
            if len(parts) < 2:
                LOG.error("backup note format error: %s", BACKUP_NOTE_FILE)
                sys.exit(1)
            result.append(parts[0])

        if not result:
            LOG.error("upgrade backup record is empty")
            sys.exit(1)
        return result

    def clear_upgrade_backup(self):
        rm_list = copy.deepcopy(self._all_backup_list)
        for backup_name in self._all_backup_list:
            for version in self._current_backup_list:
                if backup_name.endswith(version):
                    rm_list.remove(backup_name)
                    break

        for rm_version in rm_list:
            rm_dir = os.path.join(UPGRADE_BACKUP_DIR, rm_version)
            try:
                import shutil
                shutil.rmtree(rm_dir)
                LOG.info("removed backup: %s", rm_dir)
            except Exception as err:
                LOG.error("failed to remove %s: %s", rm_dir, err)


if __name__ == '__main__':
    br = BackupRemover()
    try:
        br.clear_upgrade_backup()
    except Exception as error:
        LOG.error("clear upgrade backup failed: %s", error)
        sys.exit(1)
