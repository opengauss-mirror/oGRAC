#!/usr/bin/env python3
"""oGRAC unified configuration module."""

import json
import os
import posixpath
import sys
from pathlib import Path

import importlib.util
_ACTION_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
_root_config_path = os.path.join(_ACTION_DIR, "config.py")
_spec = importlib.util.spec_from_file_location("_action_config", _root_config_path)
_action_config = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_action_config)
load_env_defaults = _action_config.load_env_defaults
load_deploy_params = _action_config.load_deploy_params
get_module_config = _action_config.get_module_config


CUR_DIR = os.path.dirname(os.path.abspath(__file__))
PKG_DIR = os.path.abspath(os.path.join(CUR_DIR, "../.."))

OGRAC_CONFIG_FILE = os.path.join(CUR_DIR, "ograc_config.json")
INSTALL_CONFIG_FILE = os.path.join(PKG_DIR, "action", "ograc", "install_config.json")
UNINSTALL_CONFIG_FILE = os.path.join(PKG_DIR, "action", "ograc", "ograc_uninstall_config.json")


class TimeoutConfig:
    _DEFAULTS = {
        "default": 1800,
        "pre_install": 600,
        "install": 7200,
        "start": 1800,
        "stop": 600,
        "check_status": 300,
        "uninstall": 3600,
        "init_container": 3600,
        "backup": 7200,
        "pre_upgrade": 3600,
        "upgrade_backup": 7200,
        "upgrade": 7200,
        "rollback": 7200,
        "post_upgrade": 3600,
    }

    def __init__(self, overrides=None):
        self._timeouts = dict(self._DEFAULTS)
        if overrides:
            for k, v in overrides.items():
                if not str(k).startswith("_"):
                    self._timeouts[k] = v

    def get(self, operation):
        seconds = self._timeouts.get(operation, self._timeouts["default"])
        return None if int(seconds) == 0 else int(seconds)


class InstanceConfig:
    def __init__(self, user="ograc", cgroup_memory_base="/sys/fs/cgroup/memory",
                 ogracd_name="ogracd", memory_limit_mb=0):
        self.user = user
        self.name = user

        self.cgroup_memory_base = cgroup_memory_base
        self.ogracd_name = ogracd_name
        self.cgroup_memory_path = posixpath.join(cgroup_memory_base, ogracd_name, user)
        self.memory_limit_mb = int(memory_limit_mb)


class PathConfig:
    """Derive paths from ograc_home/data_root + install_config.json."""

    def __init__(self, ograc_home="/opt/ograc", data_root="/mnt/dbdata",
                 install_conf=None, instance=None):
        self.instance = instance or InstanceConfig()
        self.ograc_home = ograc_home
        self.data_root = data_root

        install_conf = install_conf or {}
        self.r_install_path = install_conf.get("R_INSTALL_PATH", posixpath.join(ograc_home, "ograc", "server"))
        self.d_data_path = install_conf.get("D_DATA_PATH", posixpath.join(data_root, "local", "ograc", "tmp", "data"))
        self.log_file = install_conf.get("l_LOG_FILE", posixpath.join(ograc_home, "log", "ograc", "ograc_deploy.log"))

        self.ograc_root = posixpath.dirname(self.r_install_path)
        self.ograc_cfg_dir = posixpath.join(self.ograc_root, "cfg")

        self.ograc_conf_file = posixpath.join(self.ograc_cfg_dir, "ograc_config.json")
        self.start_status_file = posixpath.join(self.ograc_cfg_dir, "start_status.json")
        self.numa_config_file = posixpath.join(self.ograc_cfg_dir, "cpu_config.json")

        self.data_cfg_dir = posixpath.join(self.d_data_path, "cfg")
        self.ogracd_ini = posixpath.join(self.data_cfg_dir, "ogracd.ini")

        self.scripts_dir = posixpath.join(self.ograc_home, "action", "ograc")

        self.backup_dir = posixpath.join(data_root, "backup")

        self.log_dir = posixpath.dirname(self.log_file)


class DeployConfig:
    def __init__(self, uninstall_conf_file=UNINSTALL_CONFIG_FILE):
        self._params = dict(load_deploy_params())
        self._env = {}
        self._uninstall = {}

        self._load_env()
        self._load_json(uninstall_conf_file, target="_uninstall")

    def _load_json(self, path, target):
        if not os.path.exists(path):
            setattr(self, target, {})
            return
        try:
            with open(path, encoding="utf-8") as f:
                setattr(self, target, json.load(f))
        except Exception as e:
            print(f"WARNING: Failed to load json {path}: {e}", file=sys.stderr)
            setattr(self, target, {})

    def _load_env(self):
        """Load user/group from root config."""
        self._env = load_env_defaults()

    @property
    def ograc_user(self):
        return self._env.get("ograc_user", "ograc")

    @property
    def ograc_group(self):
        return self._env.get("ograc_group", "ograc")

    def get(self, key, default=""):
        return self._params.get(key, default)

    @property
    def raw_params(self):
        """Deploy params dict for ograc_ctl etc."""
        return dict(self._params)

    def uninstall_get(self, key, default=""):
        return self._uninstall.get(key, default)


class OgracConfig:
    def __init__(self, ograc_config_file=OGRAC_CONFIG_FILE):
        raw = {}
        if os.path.exists(ograc_config_file):
            try:
                with open(ograc_config_file, encoding="utf-8") as f:
                    raw = json.load(f)
            except Exception as e:
                print(f"WARNING: Failed to load ograc_config.json: {e}", file=sys.stderr)

        mc = get_module_config()
        ograc_home = os.environ.get("OGRAC_HOME", mc.get("ograc_home", raw.get("ograc_home", "/opt/ograc")))
        data_root = os.environ.get("OGRAC_DATA_ROOT", mc.get("data_root", raw.get("data_root", "/mnt/dbdata")))
        user = os.environ.get("OGRAC_USER", mc.get("user", raw.get("user", "ograc")))

        install_conf = {}
        if os.path.exists(INSTALL_CONFIG_FILE):
            try:
                with open(INSTALL_CONFIG_FILE, encoding="utf-8") as f:
                    install_conf = json.load(f)
            except Exception as e:
                print(f"WARNING: Failed to load install_config.json: {e}", file=sys.stderr)

        inst_raw = raw.get("instance", {}).get("cgroup", {})
        instance = InstanceConfig(
            user=user,
            cgroup_memory_base=inst_raw.get("memory_base", "/sys/fs/cgroup/memory"),
            ogracd_name=inst_raw.get("ogracd_name", "ogracd"),
            memory_limit_mb=inst_raw.get("memory_limit_mb", 0),
        )

        self.paths = PathConfig(ograc_home=ograc_home, data_root=data_root,
                                install_conf=install_conf, instance=instance)
        self.timeout = TimeoutConfig(raw.get("timeout", None))
        self.deploy = DeployConfig()


_global_cfg = None


def get_config():
    global _global_cfg
    if _global_cfg is None:
        _global_cfg = OgracConfig()
    return _global_cfg


class _LazyCfg:
    def __getattr__(self, name):
        return getattr(get_config(), name)


cfg = _LazyCfg()


def get_value(param):
    """Get a deploy parameter by key."""
    _cfg = get_config()
    if param in ("ograc_user",):
        return _cfg.deploy.ograc_user
    if param in ("ograc_group",):
        return _cfg.deploy.ograc_group
    if param in ("R_INSTALL_PATH", "D_DATA_PATH", "l_LOG_FILE"):
        install = {
            "R_INSTALL_PATH": _cfg.paths.r_install_path,
            "D_DATA_PATH": _cfg.paths.d_data_path,
            "l_LOG_FILE": _cfg.paths.log_file,
        }
        return install.get(param, "")
    return _cfg.deploy.get(param, "")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--shell-env":
        _cfg = get_config()
        print(f'OGRAC_HOME="{_cfg.paths.ograc_home}"')
        print(f'OGRAC_USER="{_cfg.paths.instance.user}"')
        print(f'OGRAC_LOG_FILE="{_cfg.paths.log_file}"')
        print(f'OGRAC_LOG_DIR="{_cfg.paths.log_dir}"')
        print(f'OGRAC_SCRIPTS_DIR="{_cfg.paths.scripts_dir}"')
        print(f'OGRAC_DATA_PATH="{_cfg.paths.d_data_path}"')
        print(f'OGRAC_INSTALL_PATH="{_cfg.paths.r_install_path}"')
        print(f'CGROUP_MEMORY_PATH="{_cfg.paths.instance.cgroup_memory_path}"')
    else:
        key = sys.argv[1] if len(sys.argv) > 1 else ""
        print(get_value(key))

