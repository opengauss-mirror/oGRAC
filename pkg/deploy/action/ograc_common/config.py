#!/usr/bin/env python3
"""ograc_common unified configuration module."""

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
get_module_config = _action_config.get_module_config

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
PKG_DIR = os.path.abspath(os.path.join(CUR_DIR, "../.."))

DEPLOY_PARAM_FILE = os.path.join(PKG_DIR, "config", "deploy_param.json")


class PathConfig:
    def __init__(self, ograc_home="/opt/ograc", data_root="/mnt/dbdata"):
        self.ograc_home = ograc_home
        self.data_root = data_root

        self.primary_keystore = posixpath.join(ograc_home, "common", "config", "primary_keystore_bak.ks")
        self.standby_keystore = posixpath.join(ograc_home, "common", "config", "standby_keystore_bak.ks")
        self.dbstor_lib = posixpath.join(ograc_home, "dbstor", "lib")
        self.ogsql_ini = posixpath.join(data_root, "local", "ograc", "tmp", "data", "cfg", "ogsql.ini")
        self.install_path = ograc_home
        self.backup_path = posixpath.join(data_root, "backup")
        self.cms_dir = posixpath.join(ograc_home, "cms")
        self.ograc_dir = posixpath.join(ograc_home, "ograc")
        self.dbstor_dir = posixpath.join(ograc_home, "dbstor")


def _load_deploy_param(path):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


class OgracCommonConfig:
    def __init__(self):
        mc = get_module_config()
        ograc_home = os.environ.get("OGRAC_HOME", mc.get("ograc_home", "/opt/ograc"))
        data_root = os.environ.get("OGRAC_DATA_ROOT", mc.get("data_root", "/mnt/dbdata"))
        env = load_env_defaults()
        self.user = env.get("ograc_user", "ograc")
        self.group = env.get("ograc_group", "ograc")
        self.common_group = env.get("ograc_common_group", f"{self.user}group")
        self.deploy_params = _load_deploy_param(DEPLOY_PARAM_FILE)
        self.paths = PathConfig(ograc_home=ograc_home, data_root=data_root)

    def get_deploy_param(self, key, default=""):
        return self.deploy_params.get(key, default)


_global_cfg = None


def get_config():
    global _global_cfg
    if _global_cfg is None:
        _global_cfg = OgracCommonConfig()
    return _global_cfg


class _LazyCfg:
    def __getattr__(self, name):
        return getattr(get_config(), name)


cfg = _LazyCfg()
