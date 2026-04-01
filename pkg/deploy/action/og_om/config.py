#!/usr/bin/env python3
"""og_om unified configuration module."""

import importlib.util
import json
import os
import posixpath
import re
import sys

_ACTION_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
_spec = importlib.util.spec_from_file_location("_action_config", os.path.join(_ACTION_DIR, "config.py"))
_action_config = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_action_config)
load_env_defaults = _action_config.load_env_defaults
get_module_config = _action_config.get_module_config

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
PKG_DIR = os.path.abspath(os.path.join(CUR_DIR, "../.."))

CONFIG_FILE = os.path.join(CUR_DIR, "og_om_config.json")
VERSIONS_YML = os.path.join(PKG_DIR, "versions.yml")


class TimeoutConfig:
    _DEFAULTS = {
        "default": 1800, "start": 300, "stop": 300, "check_status": 120,
        "install": 1800, "uninstall": 600, "pre_install": 600,
        "upgrade": 1800, "rollback": 1800, "post_upgrade": 600,
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


class CGroupConfig:
    def __init__(self, ograc_home, user, cgroup_raw=None):
        cgroup_raw = cgroup_raw or {}
        self.memory_base = cgroup_raw.get("memory_base", "/sys/fs/cgroup/memory")
        self.exporter_name = cgroup_raw.get("exporter_name", "ograc_exporter")
        self.ogmgr_name = cgroup_raw.get("ogmgr_name", "ogmgr")
        self.ogmgr_memory_limit = cgroup_raw.get("ogmgr_memory_limit", "2G")

        self.exporter_cgroup = posixpath.join(self.memory_base, self.exporter_name, user)
        self.ogmgr_cgroup = posixpath.join(self.memory_base, self.ogmgr_name, user)


class PathConfig:
    def __init__(self, ograc_home=None, svc=None):
        self.ograc_home = ograc_home or "/opt/ograc"
        svc = svc or {}

        self.log_dir = posixpath.join(self.ograc_home, "log", "og_om")
        self.log_file = posixpath.join(self.log_dir, "om_deploy.log")

        self.og_om_dir = posixpath.join(self.ograc_home, svc.get("og_om_dir", "og_om"))
        self.service_dir = posixpath.join(self.ograc_home, svc.get("service_dir", "og_om/service"))

        self.ogmgr_dir = posixpath.join(self.ograc_home, svc.get("ogmgr_dir", "og_om/service/ogmgr"))
        self.ogmgr_scripts = posixpath.join(self.ograc_home, svc.get("ogmgr_scripts", "og_om/service/ogmgr/scripts"))
        self.ogmgr_uds_server = posixpath.join(self.ograc_home, svc.get("ogmgr_uds_server", "og_om/service/ogmgr/uds_server.py"))

        self.ogcli_dir = posixpath.join(self.ograc_home, svc.get("ogcli_dir", "og_om/service/ogcli"))
        self.ogcli_main = posixpath.join(self.ograc_home, svc.get("ogcli_main", "og_om/service/ogcli/main.py"))
        self.ogcli_commands_json = posixpath.join(self.ogcli_dir, "commands.json")

        self.exporter_dir = posixpath.join(self.ograc_home, svc.get("exporter_dir", "og_om/service/ograc_exporter"))
        self.exporter_scripts = posixpath.join(self.ograc_home, svc.get("exporter_scripts", "og_om/service/ograc_exporter/scripts"))
        self.exporter_data = posixpath.join(self.ograc_home, svc.get("exporter_data", "og_om/service/ograc_exporter/exporter_data"))
        self.exporter_execute = posixpath.join(self.ograc_home, svc.get("exporter_execute", "og_om/service/ograc_exporter/exporter/execute.py"))

        self.action_dir = posixpath.join(self.ograc_home, "action", "og_om")
        self.repo_dir = posixpath.join(self.ograc_home, "repo")

        self.rpm_flag = posixpath.join(self.ograc_home, "installed_by_rpm")

        self.start_ogmgr_sh = posixpath.join(self.ogmgr_scripts, "start_ogmgr.sh")
        self.stop_ogmgr_sh = posixpath.join(self.ogmgr_scripts, "stop_ogmgr.sh")

        self.ogctl_path = posixpath.join(self.ograc_home, "bin", "ogctl")

        self.exporter_config_dir = posixpath.join(self.exporter_dir, "config")
        self.exporter_query_dir = posixpath.join(self.exporter_dir, "query_storage_info")
        self.exporter_exporter_dir = posixpath.join(self.exporter_dir, "exporter")
        self.ogmgr_checker_dir = posixpath.join(self.ogmgr_dir, "checker")
        self.ogmgr_logs_collection = posixpath.join(self.ogmgr_dir, "logs_collection")
        self.ogmgr_log_tool = posixpath.join(self.ogmgr_dir, "log_tool")
        self.ogmgr_tasks_dir = posixpath.join(self.ogmgr_dir, "tasks")
        self.ogmgr_common_dir = posixpath.join(self.ogmgr_dir, "common")
        self.ogmgr_tasks_inspection = posixpath.join(self.ogmgr_dir, "tasks", "inspection")
        self.ogmgr_format_note = posixpath.join(self.ogmgr_dir, "format_note.json")
        self.ogmgr_log_packing = posixpath.join(self.ogmgr_dir, "logs_collection", "log_packing_progress.json")
        self.exporter_logicrep_sql = posixpath.join(self.exporter_config_dir, "get_logicrep_info.sql")


def _parse_version(versions_file):
    """Parse version from versions.yml."""
    if not os.path.exists(versions_file):
        return ""
    try:
        with open(versions_file, encoding="utf-8") as f:
            for line in f:
                if "Version:" in line:
                    ver = line.split("Version:")[1].strip()
                    m = re.match(r'(\d+\.\d+(?:\.\d+)?)', ver)
                    return m.group(1) if m else ver
    except Exception:
        pass
    return ""


class OgOmConfig:
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
        data_root = (
            os.environ.get("DATA_ROOT")
            or module_cfg.get("data_root")
            or "/mnt/dbdata"
        )

        env = load_env_defaults()
        self.user = env.get("ograc_user", raw.get("user", "ograc"))
        self.group = env.get("ograc_group", raw.get("group", "ograc"))
        self.common_group = env.get("ograc_common_group", f"{self.user}group")
        self.ogmgr_user = env.get("ogmgr_user", f"{self.user}mgr")
        self.data_root = data_root

        self.paths = PathConfig(ograc_home=ograc_home, svc=raw.get("service"))
        self.cgroup = CGroupConfig(ograc_home, self.user, raw.get("cgroup"))
        self.timeout = TimeoutConfig(raw.get("timeout"))

        self.version = _parse_version(VERSIONS_YML)


_global_cfg = None


def get_config():
    global _global_cfg
    if _global_cfg is None:
        _global_cfg = OgOmConfig()
    return _global_cfg


class _LazyCfg:
    def __getattr__(self, name):
        return getattr(get_config(), name)


cfg = _LazyCfg()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--shell-env":
        c = get_config()
        print(f'OGRAC_HOME="{c.paths.ograc_home}"')
        print(f'OGOM_USER="{c.user}"')
        print(f'OGMGR_USER="{c.ogmgr_user}"')
        print(f'OGOM_LOG_DIR="{c.paths.log_dir}"')
        print(f'OGOM_LOG_FILE="{c.paths.log_file}"')
