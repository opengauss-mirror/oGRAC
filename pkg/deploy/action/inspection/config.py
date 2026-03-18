#!/usr/bin/env python3
"""inspection unified configuration module."""
import json
import os
import posixpath
import sys

import importlib.util
_ACTION_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
_root_config_path = os.path.join(_ACTION_DIR, "config.py")
_spec = importlib.util.spec_from_file_location("_action_config", _root_config_path)
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
        self.versions_yml = posixpath.join(ograc_home, "versions.yml")
        self.deploy_param_json = posixpath.join(ograc_home, "config", "deploy_param.json")
        self.primary_keystore = posixpath.join(ograc_home, "common", "config", "primary_keystore_bak.ks")
        self.standby_keystore = posixpath.join(ograc_home, "common", "config", "standby_keystore_bak.ks")
        self.dbstor_lib = posixpath.join(ograc_home, "dbstor", "lib")
        self.ogsql_ini = posixpath.join(data_root, "local", "ograc", "tmp", "data", "cfg", "ogsql.ini")
        self.ograc_log_run = posixpath.join(ograc_home, "log", "ograc", "run")
        self.ograc_server = posixpath.join(ograc_home, "ograc", "server")
        self.data_path = posixpath.join(data_root, "local", "ograc", "tmp", "data")
        self.logicrep_home = "/opt/software/tools/logicrep"
        self.logicrep_alarm = posixpath.join(self.logicrep_home, "logicrep", "logicrep", "alarm", "alarm.log")
        self.logicrep_enable = posixpath.join(self.logicrep_home, "enable.success")
        self.action_dir = posixpath.join(ograc_home, "action")
        self.dbstor_home = posixpath.join(ograc_home, "dbstor")
        self.dbstor_cgwshowdev_log = posixpath.join(self.dbstor_home, "cgwshowdev.log")
        self.check_link_script = posixpath.join(
            ograc_home, "action", "inspection", "inspection_scripts", "kernal", "check_link_cnt.py"
        )


def _load_deploy_param(path):
    """Load deploy_param.json."""
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"WARNING: Failed to load {path}: {e}", file=sys.stderr)
        return {}


class InspectionConfig:
    """Unified config entry for inspection module."""

    def __init__(self):
        ograc_home = os.environ.get("OGRAC_HOME", "/opt/ograc")
        data_root = os.environ.get("OGRAC_DATA_ROOT", "/mnt/dbdata")
        self.paths = PathConfig(ograc_home=ograc_home, data_root=data_root)
        self._env = load_env_defaults()
        self._deploy = _load_deploy_param(DEPLOY_PARAM_FILE)

    @property
    def ograc_user(self):
        return self._env.get("ograc_user", "ograc")

    @property
    def ograc_group(self):
        return self._env.get("ograc_group", "ograc")

    @property
    def ogmgr_user(self):
        return self._env.get("ogmgr_user", f"{self.ograc_user}mgr")

    def deploy_get(self, key, default=""):
        return self._deploy.get(key, default)


_global_cfg = None


def get_config():
    """Get global InspectionConfig singleton."""
    global _global_cfg
    if _global_cfg is None:
        _global_cfg = InspectionConfig()
    return _global_cfg


class _LazyCfg:
    """Lazy proxy for module-level cfg.paths.xxx."""
    def __getattr__(self, name):
        return getattr(get_config(), name)


cfg = _LazyCfg()
