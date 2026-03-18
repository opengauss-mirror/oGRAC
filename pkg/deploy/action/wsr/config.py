#!/usr/bin/env python3
import json
import os
import posixpath

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
ACTION_DIR = os.path.abspath(os.path.join(CUR_DIR, ".."))
MODULE_CONFIG_FILE = os.path.join(ACTION_DIR, "config_params_lun.json")

_module_config_cache = None
_deploy_params_cache = None


def _load_config_params_lun_raw():
    if not os.path.exists(MODULE_CONFIG_FILE):
        return {}
    try:
        with open(MODULE_CONFIG_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def load_deploy_params():
    global _deploy_params_cache
    if _deploy_params_cache is not None:
        return _deploy_params_cache
    raw = _load_config_params_lun_raw()
    _deploy_params_cache = {key: value for key, value in raw.items() if key != "module_config"}
    return _deploy_params_cache


def get_module_config():
    global _module_config_cache
    if _module_config_cache is not None:
        return _module_config_cache
    raw = _load_config_params_lun_raw()
    _module_config_cache = raw.get("module_config", {})
    return _module_config_cache


def load_env_defaults():
    module_cfg = get_module_config()
    user = os.environ.get("OGRAC_USER", module_cfg.get("user", "ograc"))
    group = os.environ.get("OGRAC_GROUP", user)
    return {
        "ograc_user": user,
        "ograc_group": group,
        "ograc_common_group": f"{user}group",
    }


class PathConfig:
    def __init__(self, ograc_home="/opt/ograc", data_root="/mnt/dbdata"):
        self.ograc_home = ograc_home
        self.data_root = data_root
        self.report_output_dir = posixpath.join(ograc_home, "log", "wsr")


class WsrReportConfig:
    def __init__(self):
        env = load_env_defaults()
        self.user = env.get("ograc_user", "ograc")
        self.group = env.get("ograc_group", "ograc")
        self.common_group = env.get("ograc_common_group", f"{self.user}group")
        self.deploy_params = load_deploy_params()

        module_cfg = get_module_config()
        ograc_home = os.environ.get("OGRAC_HOME", module_cfg.get("ograc_home", "/opt/ograc"))
        data_root = os.environ.get("OGRAC_DATA_ROOT", module_cfg.get("data_root", "/mnt/dbdata"))
        self.paths = PathConfig(ograc_home=ograc_home, data_root=data_root)

    def get_deploy_param(self, key, default=""):
        return self.deploy_params.get(key, default)


_global_cfg = None


def get_config():
    global _global_cfg
    if _global_cfg is None:
        _global_cfg = WsrReportConfig()
    return _global_cfg


class _LazyCfg:
    def __getattr__(self, name):
        return getattr(get_config(), name)


cfg = _LazyCfg()
