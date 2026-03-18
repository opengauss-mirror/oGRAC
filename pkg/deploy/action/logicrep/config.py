#!/usr/bin/env python3
"""logicrep unified configuration module."""

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

CONFIG_FILE = os.path.join(CUR_DIR, "logicrep_config.json")
DEPLOY_PARAM_FILE = os.path.join(PKG_DIR, "config", "deploy_param.json")
VERSIONS_YML = os.path.join(PKG_DIR, "versions.yml")


class TimeoutConfig:
    _DEFAULTS = {
        "default": 1800, "install": 1800, "start": 600, "startup": 900,
        "stop": 300, "shutdown": 600, "check_status": 120, "uninstall": 300,
        "pre_upgrade": 600, "upgrade_backup": 1800, "upgrade": 1800,
        "rollback": 1800, "init_container": 1800, "set_resource_limit": 300,
    }

    def __init__(self, overrides=None):
        self._t = dict(self._DEFAULTS)
        if overrides:
            for k, v in overrides.items():
                if not str(k).startswith("_"):
                    self._t[k] = v

    def get(self, operation):
        s = self._t.get(operation, self._t["default"])
        return None if int(s) == 0 else int(s)


class PathConfig:
    def __init__(self, ograc_home="/opt/ograc", data_root="/mnt/dbdata",
                 logicrep_home="/opt/software/tools/logicrep",
                 tools_root="/opt/software/tools",
                 logicrep_pkg_rel="zlogicrep/build/oGRAC_PKG/file"):
        self.ograc_home = ograc_home
        self.data_root = data_root

        self.logicrep_home = logicrep_home
        self.tools_root = tools_root

        self.logicrep_pkg = posixpath.join(ograc_home, "action", "..", "..",
                                           logicrep_pkg_rel)

        self.tools_home = posixpath.join(ograc_home, "logicrep")
        self.tools_scripts = posixpath.join(ograc_home, "action", "logicrep")
        self.log_dir = posixpath.join(ograc_home, "log", "logicrep")
        self.log_file = posixpath.join(self.log_dir, "logicrep_deploy.log")
        self.deploy_log = posixpath.join(ograc_home, "log", "deploy", "deploy.log")
        self.versions_yml = posixpath.join(ograc_home, "versions.yml")

        self.primary_keystore = posixpath.join(ograc_home, "common", "config", "primary_keystore_bak.ks")
        self.standby_keystore = posixpath.join(ograc_home, "common", "config", "standby_keystore_bak.ks")
        self.kmc_shared_dir = posixpath.join(ograc_home, "image", "oGRAC-RUN-LINUX-64bit", "kmc_shared")
        self.dbstor_lib = posixpath.join(ograc_home, "dbstor", "lib")

        self.conf_dir = posixpath.join(logicrep_home, "conf")
        self.init_properties = posixpath.join(logicrep_home, "conf", "init.properties")
        self.datasource_properties = posixpath.join(logicrep_home, "conf", "datasource.properties")
        self.sec_dir = posixpath.join(logicrep_home, "conf", "sec")
        self.key1_file = posixpath.join(self.sec_dir, "primary_keystore.ks")
        self.key2_file = posixpath.join(self.sec_dir, "standby_keystore.ks")
        self.flag_file = posixpath.join(logicrep_home, "start.success")
        self.enable_file = posixpath.join(logicrep_home, "enable.success")
        self.user_file = posixpath.join(logicrep_home, "create_user.json")
        self.watchdog_sh = posixpath.join(logicrep_home, "watchdog_logicrep.sh")
        self.watchdog_shutdown_sh = posixpath.join(logicrep_home, "watchdog_shutdown.sh")
        self.shutdown_sh = posixpath.join(logicrep_home, "shutdown.sh")
        self.logicrep_lib = posixpath.join(logicrep_home, "lib")

        self.ogsql_ini_glob = posixpath.join(data_root, "local", "ograc", "tmp", "data", "cfg", "*sql.ini")
        self.data_path = posixpath.join(data_root, "local", "ograc", "tmp", "data")


def _load_deploy_param(path):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


class LogicrepConfig:
    def __init__(self, config_file=CONFIG_FILE):
        raw = {}
        if os.path.exists(config_file):
            try:
                with open(config_file, encoding="utf-8") as f:
                    raw = json.load(f)
            except Exception as e:
                print(f"WARNING: load config failed: {e}", file=sys.stderr)

        ograc_home = os.environ.get("OGRAC_HOME", raw.get("ograc_home", "/opt/ograc"))
        data_root = os.environ.get("OGRAC_DATA_ROOT", raw.get("data_root", "/mnt/dbdata"))
        logicrep_home = raw.get("logicrep_home", "/opt/software/tools/logicrep")
        tools_root = raw.get("logicrep_tools_root", "/opt/software/tools")
        pkg_rel = raw.get("logicrep_pkg_rel", "zlogicrep/build/oGRAC_PKG/file")

        env = load_env_defaults()
        self.user = env.get("ograc_user", raw.get("user", "ograc"))
        self.group = env.get("ograc_group", raw.get("group", "ograc"))

        self.deploy_params = _load_deploy_param(DEPLOY_PARAM_FILE)
        self.paths = PathConfig(ograc_home=ograc_home, data_root=data_root,
                                logicrep_home=logicrep_home, tools_root=tools_root,
                                logicrep_pkg_rel=pkg_rel)
        self.timeout = TimeoutConfig(raw.get("timeout"))

        self.so_names = raw.get("so_names", {
            "libssl.so": "libssl.so.10", "libcrypto.so": "libcrypto.so.10",
            "libstdc++.so": "libstdc++.so.6", "libsql2bl.so": "libsql2bl.so",
        })
        self.driver_name = raw.get("driver_name", "com.huawei.ograc.jdbc.ogracDriver-ograc.jar")

    def get_deploy_param(self, key, default=""):
        return self.deploy_params.get(key, default)


_global_cfg = None


def get_config():
    global _global_cfg
    if _global_cfg is None:
        _global_cfg = LogicrepConfig()
    return _global_cfg


class _LazyCfg:
    def __getattr__(self, name):
        return getattr(get_config(), name)


cfg = _LazyCfg()


def get_value(param):
    """Get a deploy parameter by key."""
    c = get_config()
    if param in ("ograc_user",):
        return c.user
    if param in ("ograc_group",):
        return c.group
    return c.get_deploy_param(param, "")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--shell-env":
        c = get_config()
        print(f'OGRAC_HOME="{c.paths.ograc_home}"')
        print(f'LOGICREP_USER="{c.user}"')
        print(f'LOGICREP_LOG_DIR="{c.paths.log_dir}"')
        print(f'LOGICREP_LOG_FILE="{c.paths.log_file}"')
        print(f'LOGICREP_HOME="{c.paths.logicrep_home}"')
    else:
        key = sys.argv[1] if len(sys.argv) > 1 else ""
        print(get_value(key))
