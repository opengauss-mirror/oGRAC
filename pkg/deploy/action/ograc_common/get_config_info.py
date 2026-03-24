#!/usr/bin/env python3
"""Deploy parameter lookup."""

import json
import sys
import os

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, CUR_DIR)

from config import cfg as _cfg

_OGRAC_CFG_DIR = os.path.join(_cfg.paths.ograc_dir, "cfg")
_ACTION_DIR = os.path.abspath(os.path.join(CUR_DIR, ".."))

_NUMA_PARAMS = ("OGRAC_NUMA_CPU_INFO", "KERNEL_NUMA_CPU_INFO")
_NUMA_CONFIG_FILE = os.path.join(_OGRAC_CFG_DIR, "cpu_config.json")

_START_STATUS_FILE = os.path.join(_OGRAC_CFG_DIR, "start_status.json")
_START_STATUS_PARAMS = {
    "OGRAC_EVER_START": "ever_started",
    "OGRAC_START_STATUS": "start_status",
    "OGRAC_DB_CREATE_STATUS": "db_create_status",
}

_INSTALL_CONFIG_FILE = os.path.join(_ACTION_DIR, "ograc", "install_config.json")


def _load_json(path):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


_install_config_cache = None


def _get_install_config():
    global _install_config_cache
    if _install_config_cache is None:
        _install_config_cache = _load_json(_INSTALL_CONFIG_FILE)
    return _install_config_cache


def get_value(param):
    if param in ("deploy_user", "ograc_user"):
        return _cfg.user
    if param in ("deploy_group", "ograc_group"):
        return _cfg.group
    if param in _NUMA_PARAMS:
        return _load_json(_NUMA_CONFIG_FILE).get(param, "")
    if param in _START_STATUS_PARAMS:
        return _load_json(_START_STATUS_FILE).get(_START_STATUS_PARAMS[param], "")
    ic = _get_install_config()
    if param in ic:
        return ic[param]
    return _cfg.get_deploy_param(param, "")


if __name__ == "__main__":
    _param = sys.argv[1]
    res = get_value(_param)
    print(res)
