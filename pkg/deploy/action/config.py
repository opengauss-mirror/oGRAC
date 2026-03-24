#!/usr/bin/env python3
"""oGRAC unified configuration module."""

import os
import sys
import json
import stat
import hashlib


CUR_DIR = os.path.dirname(os.path.abspath(__file__))
PKG_DIR = os.path.abspath(os.path.join(CUR_DIR, ".."))
MODULE_CONFIG_FILE = os.path.join(CUR_DIR, "config_params_lun.json")


_TIMEOUTS_DEFAULT = {
    "default": 1800, "install": 3600, "uninstall": 1800,
    "upgrade": 3600, "pre_install": 1800, "start": 600,
    "stop": 600, "check_status": 120, "backup": 7200,
    "rollback": 3600, "pre_upgrade": 1800, "upgrade_commit": 600,
    "init_container": 1800,
}

_OGRAC_CONFIG_FILE = os.path.join(CUR_DIR, "ograc", "ograc_config.json")


def _load_timeouts():
    timeouts = dict(_TIMEOUTS_DEFAULT)
    if os.path.exists(_OGRAC_CONFIG_FILE):
        try:
            with open(_OGRAC_CONFIG_FILE, encoding="utf-8") as f:
                overrides = json.load(f).get("timeout", {})
            for k, v in overrides.items():
                if not str(k).startswith("_"):
                    timeouts[k] = int(v)
        except Exception:
            pass
    return timeouts


_TIMEOUTS = _load_timeouts()

_module_config_cache = None
_deploy_params_cache = None


def _derive_instance_tag(ograc_home):
    real_home = os.path.realpath(ograc_home)
    digest = hashlib.sha256(real_home.encode("utf-8")).hexdigest()
    return digest[:8]


def _load_config_params_lun_raw():
    """Read full content of config_params_lun.json."""
    if not os.path.exists(MODULE_CONFIG_FILE):
        return {}
    try:
        with open(MODULE_CONFIG_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def load_deploy_params():
    """Read deploy params from config_params_lun.json (excl module_config)."""
    global _deploy_params_cache
    if _deploy_params_cache is not None:
        return _deploy_params_cache
    raw = _load_config_params_lun_raw()
    _deploy_params_cache = {k: v for k, v in raw.items() if k != "module_config"}
    return _deploy_params_cache


def _get_module_config():
    global _module_config_cache
    if _module_config_cache is not None:
        return _module_config_cache
    raw = _load_config_params_lun_raw()
    _module_config_cache = raw.get("module_config", {})
    return _module_config_cache


def get_module_config():
    """Return module_config block from config_params_lun.json."""
    return _get_module_config()


_DEFAULT_NFS_PORT = 36729


def load_env_defaults():
    """Derive user/group/common_group/ogmgr_user from module_config."""
    mc = _get_module_config()
    user = os.environ.get("OGRAC_USER") or mc.get("user") or "ograc"
    group = os.environ.get("OGRAC_GROUP", user)
    common_group = f"{user}group"
    ogmgr_user = f"{user}mgr"
    return {
        "ograc_user": user,
        "ograc_group": group,
        "ograc_common_group": common_group,
        "ogmgr_user": ogmgr_user,
        "nfs_port": _DEFAULT_NFS_PORT,
    }


class InstanceConfig:
    """cgroup/shm isolation, user as key."""

    def __init__(self, user="ograc"):
        self.user = user
        self.cgroup_memory_base = "/sys/fs/cgroup/memory"
        self.cgroup_memory_path = os.path.join(self.cgroup_memory_base, "cms", user)
        self.cgroup_memory_limit_gb = 10
        self.shm_base = "/dev/shm"
        self.shm_home = os.path.join(self.shm_base, user)
        self.shm_pattern = f"ograc.[0-9]*"


class LogConfig:
    """Log isolation: log_root/<module>/<module>.log."""

    def __init__(self, log_root):
        self.log_root = log_root

    def log_dir(self, module):
        return os.path.join(self.log_root, module)

    def log_file(self, module):
        return os.path.join(self.log_root, module, f"{module}.log")


class PathConfig:
    """Derive all paths from ograc_home + data_root + user."""

    def __init__(self, ograc_home, data_root, user):
        self.ograc_home = ograc_home
        self.data_root = data_root
        self.user = user
        self.instance = InstanceConfig(user)
        self.instance_tag = _derive_instance_tag(ograc_home)

        self.action_dir = os.path.join(ograc_home, "action")
        self.config_dir = os.path.join(ograc_home, "config")
        self.image_dir = os.path.join(ograc_home, "image")
        self.backup_dir = os.path.join(data_root, "backup")
        self.common_dir = os.path.join(ograc_home, "common")
        self.common_script_dir = os.path.join(self.common_dir, "script")
        self.common_config_dir = os.path.join(ograc_home, "common", "config")
        self.certificates_dir = os.path.join(ograc_home, "common", "config", "certificates")
        self.cms_home = os.path.join(ograc_home, "cms")
        self.cms_cfg_dir = os.path.join(ograc_home, "cms", "cfg")
        self.ograc_app_home = os.path.join(ograc_home, "ograc")
        self.og_om_dir = os.path.join(ograc_home, "og_om")
        self.rpm_pack_path = os.path.join(ograc_home, "image", "oGRAC-RUN-LINUX-64bit")
        self.rpm_flag = os.path.join(ograc_home, "installed_by_rpm")
        self.versions_yml = os.path.join(ograc_home, "versions.yml")
        self.stop_enable = os.path.join(ograc_home, "stop.enable")
        self.upgrade_backup_root = os.path.join(ograc_home, "upgrade_backup")
        self.deploy_log_dir = os.path.join(ograc_home, "log", "deploy")
        self.deploy_daemon_log = os.path.join(self.deploy_log_dir, "deploy_daemon.log")
        self.ograc_service_script = os.path.join(self.common_script_dir, "ograc_service.sh")
        self.ograc_daemon_script = os.path.join(self.common_script_dir, "ograc_daemon.sh")
        self.rerun_script = os.path.join(self.common_script_dir, "rerun.sh")
        self.daemon_service_unit = f"ograc-{self.instance_tag}.service"
        self.daemon_timer_unit = f"ograc-{self.instance_tag}.timer"
        self.logs_service_unit = f"ograc-logs-handler-{self.instance_tag}.service"
        self.logs_timer_unit = f"ograc-logs-handler-{self.instance_tag}.timer"

        self.data_local = os.path.join(data_root, "local")
        self.data_remote = os.path.join(data_root, "remote")
        self.ogracd_ini = os.path.join(
            data_root, "local", "ograc", "tmp", "data", "cfg", "ogracd.ini")

        cc = self.common_config_dir
        self.primary_keystore = os.path.join(cc, "primary_keystore.ks")
        self.standby_keystore = os.path.join(cc, "standby_keystore.ks")
        self.primary_keystore_bak = os.path.join(cc, "primary_keystore_bak.ks")
        self.standby_keystore_bak = os.path.join(cc, "standby_keystore_bak.ks")

    def share_path(self, fs_name):
        return os.path.join(self.data_remote, f"share_{fs_name}")

    def archive_path(self, fs_name):
        return os.path.join(self.data_remote, f"archive_{fs_name}")

    def metadata_path(self, fs_name):
        return os.path.join(self.data_remote, f"metadata_{fs_name}")

    def storage_path(self, fs_name):
        return os.path.join(self.data_remote, f"storage_{fs_name}")

    def upgrade_backup_path(self, version):
        return os.path.join(self.upgrade_backup_root, f"ograc_upgrade_bak_{version}")


class DeployConfig:
    """Load config_params_lun.json (deploy params + module_config)."""

    def __init__(self, deploy_param_file=None):
        self._params = {}
        self._config_file = MODULE_CONFIG_FILE
        self._load_deploy_params()
        self._env = load_env_defaults()

    def _load_deploy_params(self):
        self._params = dict(load_deploy_params())

    def get(self, key, default=""):
        if key == "cluster_scale":
            cms_ip = self._params.get("cms_ip", "")
            return len(cms_ip.split(";")) if cms_ip else 0
        if key == "dss_vg_list":
            vg_dict = self._params.get("dss_vg_list", {})
            if isinstance(vg_dict, dict):
                return ";".join(vg_dict.values())
            return str(vg_dict)
        return self._params.get(key, default)

    def get_required(self, key):
        value = self.get(key)
        if value == "" or value is None:
            raise ValueError(f"Required config key not found: {key}")
        return value

    @property
    def ograc_user(self):
        return self._env.get("ograc_user", "ograc")

    @property
    def ograc_group(self):
        return self._env.get("ograc_group", self.ograc_user)

    @property
    def ograc_common_group(self):
        return self._env.get("ograc_common_group", f"{self.ograc_user}group")

    @property
    def ogmgr_user(self):
        return self._env.get("ogmgr_user", f"{self.ograc_user}mgr")

    @property
    def deploy_mode(self):
        return self._params.get("deploy_mode", "")

    @property
    def ograc_in_container(self):
        return self._params.get("ograc_in_container", "0")

    @property
    def node_id(self):
        return self._params.get("node_id", "0")

    @property
    def storage_share_fs(self):
        return self._params.get("storage_share_fs", "")

    @property
    def storage_archive_fs(self):
        return self._params.get("storage_archive_fs", "")

    @property
    def storage_metadata_fs(self):
        return self._params.get("storage_metadata_fs", "")

    @property
    def mes_ssl_switch(self):
        return self._params.get("mes_ssl_switch", False)

    @property
    def raw_params(self):
        return dict(self._params)

    def write_param(self, key, value):
        self._params[key] = value
        raw = _load_config_params_lun_raw()
        raw.update(self._params)
        if "module_config" not in raw:
            raw["module_config"] = _get_module_config()
        modes = stat.S_IRWXU | stat.S_IROTH | stat.S_IRGRP
        flag = os.O_RDWR | os.O_CREAT | os.O_TRUNC
        with os.fdopen(os.open(self._config_file, flag, modes), 'w') as f:
            f.write(json.dumps(raw, indent=4))
        global _deploy_params_cache
        _deploy_params_cache = dict(self._params)


class OgracConfig:
    """Config entry point."""

    def __init__(self, module_config_file=None, deploy_param_file=None):
        mc = _get_module_config()

        ograc_home = os.environ.get("OGRAC_HOME", mc.get("ograc_home", "/opt/ograc"))
        data_root = os.environ.get("OGRAC_DATA_ROOT", mc.get("data_root", "/mnt/dbdata"))
        user = os.environ.get("OGRAC_USER", mc.get("user", "ograc"))

        self.paths = PathConfig(ograc_home, data_root, user)
        self.logs = LogConfig(os.path.join(ograc_home, "log"))
        self.deploy = DeployConfig(deploy_param_file)

    @staticmethod
    def timeout(operation):
        seconds = _TIMEOUTS.get(operation, _TIMEOUTS["default"])
        return None if seconds == 0 else seconds

    def get(self, key, default=""):
        return self.deploy.get(key, default)


_global_config = None


def get_config(module_config_file=None, deploy_param_file=None, env_file=None):
    """Return the singleton OgracConfig instance."""
    global _global_config
    if _global_config is None:
        _global_config = OgracConfig(module_config_file, deploy_param_file)
    return _global_config


def reset_config():
    global _global_config, _module_config_cache, _deploy_params_cache
    _global_config = None
    _module_config_cache = None
    _deploy_params_cache = None


class _LazyConfig:
    def __getattr__(self, name):
        return getattr(get_config(), name)


cfg = _LazyConfig()


def get_value(param):
    """Get a deploy parameter by key."""
    return get_config().get(param)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        param = sys.argv[1]
        if param == "--shell-env":
            _cfg = get_config()
            print(f'OGRAC_HOME="{_cfg.paths.ograc_home}"')
            print(f'OGRAC_ACTION_DIR="{_cfg.paths.action_dir}"')
            print(f'COMMON_SCRIPT_DIR="{_cfg.paths.common_script_dir}"')
            print(f'DEPLOY_LOG_DIR="{_cfg.logs.log_dir("deploy")}"')
            print(f'OM_DEPLOY_LOG_FILE="{_cfg.logs.log_file("deploy")}"')
            print(f'DEPLOY_DAEMON_LOG="{_cfg.paths.deploy_daemon_log}"')
            print(f'OGRAC_USER="{_cfg.deploy.ograc_user}"')
            print(f'OGRAC_GROUP="{_cfg.deploy.ograc_group}"')
            print(f'OGRAC_DAEMON_SERVICE="{_cfg.paths.daemon_service_unit}"')
            print(f'OGRAC_DAEMON_TIMER="{_cfg.paths.daemon_timer_unit}"')
            print(f'OGRAC_LOGS_SERVICE="{_cfg.paths.logs_service_unit}"')
            print(f'OGRAC_LOGS_TIMER="{_cfg.paths.logs_timer_unit}"')
        else:
            print(get_value(param))
