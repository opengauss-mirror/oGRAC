#!/usr/bin/env python3
"""ograc_exporter unified configuration module."""

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

CONFIG_FILE = os.path.join(CUR_DIR, "ograc_exporter_config.json")


class TimeoutConfig:
    _DEFAULTS = {
        "default": 600, "start": 120, "stop": 120, "check_status": 60,
        "install": 600, "uninstall": 300, "upgrade": 600, "rollback": 600,
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
    def __init__(self, ograc_home=None, svc=None):
        self.ograc_home = ograc_home or "/opt/ograc"
        svc = svc or {}

        self.log_dir = posixpath.join(self.ograc_home, "log", "ograc_exporter")
        self.log_file = posixpath.join(self.log_dir, "ograc_exporter.log")

        self.service_base = posixpath.join(self.ograc_home, svc.get("base_dir", "og_om/service/ograc_exporter"))
        self.scripts_dir = posixpath.join(self.ograc_home, svc.get("scripts_dir", "og_om/service/ograc_exporter/scripts"))
        self.exporter_dir = posixpath.join(self.ograc_home, svc.get("exporter_dir", "og_om/service/ograc_exporter/exporter"))
        self.data_dir = posixpath.join(self.ograc_home, svc.get("data_dir", "og_om/service/ograc_exporter/exporter_data"))
        self.execute_py = posixpath.join(self.ograc_home, svc.get("execute_py", "og_om/service/ograc_exporter/exporter/execute.py"))

        self.og_om_dir = posixpath.join(self.ograc_home, "og_om")
        self.og_om_service_dir = posixpath.join(self.ograc_home, "og_om", "service")

        self.action_dir = posixpath.join(self.ograc_home, "action", "ograc_exporter")
        self.deploy_logs_dir = posixpath.join(self.ograc_home, "log", "deploy", "logs")

        self.rpm_flag = posixpath.join(self.ograc_home, "installed_by_rpm")

        self.start_script = posixpath.join(self.scripts_dir, "start_ograc_exporter.sh")
        self.stop_script = posixpath.join(self.scripts_dir, "stop_ograc_exporter.sh")


class ExporterConfig:
    def __init__(self, config_file=CONFIG_FILE):
        raw = {}
        if os.path.exists(config_file):
            try:
                with open(config_file, encoding="utf-8") as f:
                    raw = json.load(f)
            except Exception as e:
                print(f"WARNING: load config failed: {e}", file=sys.stderr)

        module_cfg = get_module_config()
        ograc_home = (
            os.environ.get("OGRAC_HOME")
            or module_cfg.get("ograc_home")
            or raw.get("ograc_home")
            or "/opt/ograc"
        )
        env = load_env_defaults()
        self.user = env.get("ograc_user", raw.get("user", "ograc"))
        self.group = env.get("ograc_group", self.user)
        self.common_group = env.get("ograc_common_group", f"{self.user}group")

        self.paths = PathConfig(ograc_home=ograc_home, svc=raw.get("service"))
        self.timeout = TimeoutConfig(raw.get("timeout"))


_global_cfg = None


def get_config():
    global _global_cfg
    if _global_cfg is None:
        _global_cfg = ExporterConfig()
    return _global_cfg


class _LazyCfg:
    def __getattr__(self, name):
        return getattr(get_config(), name)


cfg = _LazyCfg()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--shell-env":
        c = get_config()
        print(f'OGRAC_HOME="{c.paths.ograc_home}"')
        print(f'EXPORTER_USER="{c.user}"')
        print(f'EXPORTER_LOG_DIR="{c.paths.log_dir}"')
        print(f'EXPORTER_LOG_FILE="{c.paths.log_file}"')
