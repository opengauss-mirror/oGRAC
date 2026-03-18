#!/usr/bin/env python3
import os
import pwd
import sys
from pathlib import Path

_CUR_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _CUR_DIR)

from config import get_config

_cfg = get_config()
_paths = _cfg.paths


class DeclearEnv:
    def __init__(self):
        self.version_file = str(Path(_paths.versions_yml))
        self.root_id = 0

    @staticmethod
    def get_run_user():
        _cfg_local = get_config()
        return _cfg_local.ograc_user

    def get_env_type(self):
        """
        get current environment is ograc
        :return:
            string: ograc
        """
        if os.path.exists(self.version_file):
            return 'ograc'

        return 'invalid_env'

    def get_executor(self):
        """
        get name of the user, who is executing this processing
        :return:
            string: name of the user, such as root.
        """
        user_id = os.getuid()
        if user_id == self.root_id:
            return "root"

        run_user = self.get_run_user()
        user_info = pwd.getpwnam(run_user)
        if user_id == user_info.pw_uid:
            return run_user

        raise ValueError("[error] executor must be root or ograc service user")
