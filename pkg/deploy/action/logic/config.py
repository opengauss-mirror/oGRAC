#!/usr/bin/env python3
"""logic unified configuration module."""

import importlib.util
import json
import os
import posixpath
import sys

_ACTION_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
_spec = importlib.util.spec_from_file_location("_action_config", os.path.join(_ACTION_DIR, "config.py"))
_action_config = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_action_config)
load_env_defaults = _action_config.load_env_defaults

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
PKG_DIR = os.path.abspath(os.path.join(CUR_DIR, "../.."))

DEPLOY_PARAM_FILE = os.path.join(PKG_DIR, "config", "deploy_param.json")


class PathConfig:
    def __init__(self, ograc_home="/opt/ograc", data_root="/mnt/dbdata"):
        self.ograc_home = ograc_home
        self.data_root = data_root
        self.remote_data = posixpath.join(data_root, "remote")


class LogicConfig:
    def __init__(self):
        ograc_home = os.environ.get("OGRAC_HOME", "/opt/ograc")
        data_root = os.environ.get("OGRAC_DATA_ROOT", "/mnt/dbdata")
        env = load_env_defaults()
        self.user = env.get("ograc_user", "ograc")
        self.group = env.get("ograc_group", "ograc")
        self.paths = PathConfig(ograc_home=ograc_home, data_root=data_root)


_global_cfg = None


def get_config():
    global _global_cfg
    if _global_cfg is None:
        _global_cfg = LogicConfig()
    return _global_cfg


class _LazyCfg:
    def __getattr__(self, name):
        return getattr(get_config(), name)


cfg = _LazyCfg()
