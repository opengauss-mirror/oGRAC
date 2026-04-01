#!/usr/bin/env python3
"""storage_operate unified configuration module."""
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
        self.deploy_param_json = posixpath.join(ograc_home, "config", "deploy_param.json")
        self.remote_data = posixpath.join(data_root, "remote")
        self.local_data = posixpath.join(data_root, "local", "ograc", "tmp", "data")
        self.ogsql_ini = posixpath.join(self.local_data, "cfg", "ogsql.ini")
        self.image_dir = posixpath.join(ograc_home, "image")
        self.og_om_dir = posixpath.join(ograc_home, "og_om")
        self.config_dir = posixpath.join(ograc_home, "config")
        self.deploy_log = posixpath.join(ograc_home, "log", "deploy", "deploy.log")
        self.dr_deploy_log = posixpath.join(ograc_home, "log", "deploy", "om_deploy", "dr_deploy.log")
        self.dbstor_lib = posixpath.join(ograc_home, "dbstor", "lib")
        self.dbstor_tools = posixpath.join(ograc_home, "dbstor", "tools")
        self.cs_baseline_sh = posixpath.join(self.dbstor_tools, "cs_baseline.sh")
        self.exporter_execute_py = posixpath.join(
            ograc_home, "og_om", "service", "ograc_exporter", "exporter", "execute.py"
        )
        self.install_path = ograc_home
        self.backup_path = posixpath.join(data_root, "backup")


def _load_deploy_param(path):
    """Read deploy_param.json."""
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"WARNING: Failed to load {path}: {e}", file=sys.stderr)
        return {}


class StorageOperateConfig:
    """Unified configuration entry for storage_operate module."""

    def __init__(self, config_file=None):
        raw = {}
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, encoding="utf-8") as f:
                    raw = json.load(f)
            except Exception as e:
                print(f"WARNING: Failed to load {config_file}: {e}", file=sys.stderr)

        ograc_home = os.environ.get("OGRAC_HOME", raw.get("ograc_home", "/opt/ograc"))
        data_root = os.environ.get("OGRAC_DATA_ROOT", raw.get("data_root", "/mnt/dbdata"))

        self.paths = PathConfig(ograc_home=ograc_home, data_root=data_root)
        self._deploy_param = _load_deploy_param(DEPLOY_PARAM_FILE)
        self._env = load_env_defaults()

    @property
    def ograc_user(self):
        return self._env.get("ograc_user", "ograc")

    @property
    def ograc_group(self):
        return self._env.get("ograc_group", "ograc")

    @property
    def ograc_common_group(self):
        return self._env.get("ograc_common_group", f"{self.ograc_user}group")

    def get(self, key, default=""):
        return self._deploy_param.get(key, default)


_global_cfg = None


def get_config():
    global _global_cfg
    if _global_cfg is None:
        _global_cfg = StorageOperateConfig()
    return _global_cfg


class _LazyCfg:
    def __getattr__(self, name):
        return getattr(get_config(), name)


cfg = _LazyCfg()
