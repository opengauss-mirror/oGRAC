#!/usr/bin/env python3
"""DSS unified configuration module."""

import os
import sys
import json
import hashlib

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
DSS_CONFIG_FILE = os.path.join(CUR_DIR, "dss_config.json")
_MAX_SHM_KEY = 0x7FFFFFFF


def _resolve_pkg_dir():
    """Get deploy package root: prefer marker file, fallback to relative path."""
    marker = os.path.join(os.path.dirname(CUR_DIR), ".deploy_pkg_dir")
    if os.path.isfile(marker):
        with open(marker) as f:
            d = f.read().strip()
        if os.path.isdir(d):
            return d
    return os.environ.get("DEPLOY_PKG_DIR", PKG_DIR)


def derive_shm_key(ograc_home, user=""):
    identity = f"{os.path.realpath(ograc_home)}:{user or ''}"
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    return (int(digest[:8], 16) % (_MAX_SHM_KEY - 1)) + 1


def _resolve_required_ograc_home(legacy_value=""):
    ograc_home = os.environ.get("OGRAC_HOME") or get_module_config().get("ograc_home") or legacy_value
    if not ograc_home:
        raise ValueError("module_config.ograc_home is required for DSS config")
    return os.path.realpath(ograc_home)


def _resolve_required_data_root(legacy_value=""):
    data_root = os.environ.get("OGRAC_DATA_ROOT") or get_module_config().get("data_root") or legacy_value
    if not data_root:
        raise ValueError("module_config.data_root is required for DSS config")
    return os.path.realpath(data_root)


def _resolve_required_ograc_user(legacy_value=""):
    env_defaults = load_env_defaults()
    user = os.environ.get("OGRAC_USER") or get_module_config().get("user") or legacy_value or env_defaults.get("ograc_user")
    if not user:
        raise ValueError("module_config.user is required for DSS config")
    return user


class InstanceConfig:
    """Instance config: user as key for multi-user resource isolation."""

    def __init__(self, user,
                 cgroup_memory_base="/sys/fs/cgroup/memory",
                 cgroup_memory_limit_gb=8,
                 shm_base="/dev/shm",
                 shm_prefix="ograc"):
        self.user = user
        self.name = user

        self.cgroup_memory_base = cgroup_memory_base
        self.cgroup_memory_path = os.path.join(cgroup_memory_base, "dss", user)
        self.cgroup_memory_limit_gb = cgroup_memory_limit_gb

        self.shm_base = shm_base
        self.shm_prefix = shm_prefix
        self.shm_home = os.path.join(shm_base, user)
        self.shm_pattern = f"{shm_prefix}.[0-9]*"

    def __repr__(self):
        return (f"InstanceConfig(user={self.user!r}, "
                f"cgroup={self.cgroup_memory_path!r}, "
                f"shm_home={self.shm_home!r})")


class TimeoutConfig:
    """Operation timeout config."""

    _DEFAULTS = {
        "default":       1800,
        "install":       3600,
        "uninstall":     1800,
        "upgrade":       3600,
        "pre_install":    600,
        "start":          600,
        "stop":           300,
        "check_status":   120,
        "upgrade_backup": 3600,
    }

    def __init__(self, overrides=None):
        self._timeouts = dict(self._DEFAULTS)
        if overrides:
            for k, v in overrides.items():
                if not k.startswith("_"):
                    self._timeouts[k] = v

    def get(self, operation):
        seconds = self._timeouts.get(operation, self._timeouts["default"])
        return None if seconds == 0 else int(seconds)


class PathConfig:
    """Derive all paths from ograc_home for path decoupling."""

    def __init__(self, ograc_home, data_root,
                 instance=None):
        if instance is None:
            raise ValueError("instance is required for DSS PathConfig")
        self.instance = instance

        self.ograc_home = ograc_home
        self.data_root = data_root

        self.dss_home = os.path.join(ograc_home, "dss")
        self.dss_cfg_dir = os.path.join(self.dss_home, "cfg")
        self.dss_bin_dir = os.path.join(self.dss_home, "bin")
        self.dss_lib_dir = os.path.join(self.dss_home, "lib")
        self.dss_inst_ini = os.path.join(self.dss_cfg_dir, "dss_inst.ini")
        self.dss_vg_ini = os.path.join(self.dss_cfg_dir, "dss_vg_conf.ini")

        self.cms_service_dir = os.path.join(ograc_home, "cms", "service")

        self.log_root = os.path.join(ograc_home, "log")
        self.dss_log_dir = os.path.join(self.log_root, "dss")
        self.dss_deploy_log = os.path.join(self.dss_log_dir, "dss_deploy.log")
        self.dss_run_log = os.path.join(self.dss_log_dir, "run", "dssinstance.rlog")

        self.action_dir = os.path.join(ograc_home, "action")
        self.dss_scripts_dir = os.path.join(self.action_dir, "dss")
        self.dss_control_script = os.path.join(self.dss_scripts_dir, "dss_contrl.sh")

        self.source_dir = os.path.join(_resolve_pkg_dir(), "dss")

        self.backup_dir = os.path.join(data_root, "backup", "files", "dss")

        self.install_config = os.path.join(_ACTION_DIR, "config_params_lun.json")
        self.rpm_flag = os.path.join(ograc_home, "installed_by_rpm")

        self.cgroup_memory_path = self.instance.cgroup_memory_path
        self.cgroup_default_mem_size_gb = self.instance.cgroup_memory_limit_gb
        self.shm_home = self.instance.shm_home


class DssSpecificConfig:
    """DSS-specific config (retry count, cmd timeout, etc.)."""

    def __init__(self, retry_times=20, cmd_timeout=60, init_disk_timeout=300):
        self.retry_times = retry_times
        self.cmd_timeout = cmd_timeout
        self.init_disk_timeout = init_disk_timeout


class DeployConfig:
    """Load from root config load_deploy_params() + load_env_defaults()."""

    def __init__(self, env_file=None):
        self._params = dict(load_deploy_params())
        self._env = {}
        self._load_env()

    def _load_env(self):
        """Load user/group from root config (user derives group/common_group)."""
        self._env = load_env_defaults()

    def get(self, key, default=""):
        if key in ("ograc_user",):
            return self._env.get("ograc_user", default)
        if key in ("ograc_group",):
            return self._env.get("ograc_group", default)
        return self._params.get(key, default)

    def get_required(self, key):
        value = self.get(key)
        if value == "" or value is None:
            raise ValueError(f"Required config key not found: {key}")
        return value

    @property
    def ograc_user(self):
        return self._env["ograc_user"]

    @property
    def ograc_group(self):
        return self._env["ograc_group"]

    @property
    def node_id(self):
        return self._params.get("node_id", "0")

    @property
    def cms_ip(self):
        return self._params.get("cms_ip", "")

    @property
    def dss_port(self):
        return self._params.get("dss_port", "")

    @property
    def mes_ssl_switch(self):
        return self._params.get("mes_ssl_switch", "")

    @property
    def raw_params(self):
        return dict(self._params)

    @property
    def dss_shm_key(self):
        configured = self._params.get("_SHM_KEY", "")
        if str(configured).isdigit():
            value = int(configured)
            if 1 <= value <= _MAX_SHM_KEY:
                return value
        ograc_home = _resolve_required_ograc_home(self._params.get("ograc_home", ""))
        return derive_shm_key(ograc_home, self.ograc_user)


class DssConfig:
    """DSS config entry - global singleton."""

    def __init__(self, dss_config_file=None, deploy_param_file=None, env_file=None):
        self.paths, self.timeout, self.dss, self._user = self._load_dss_config(
            dss_config_file or DSS_CONFIG_FILE
        )
        self.deploy = DeployConfig()

    @staticmethod
    def _load_dss_config(config_file):
        ograc_home = ""
        data_root = ""
        user = ""

        cgroup_memory_base = "/sys/fs/cgroup/memory"
        cgroup_memory_limit_gb = 8
        shm_base = "/dev/shm"
        shm_prefix = "ograc"

        timeout_overrides = None
        dss_retry = 20
        dss_cmd_timeout = 60
        dss_init_timeout = 300

        if os.path.exists(config_file):
            try:
                with open(config_file, encoding="utf-8") as f:
                    raw = json.load(f)
                ograc_home = raw.get("ograc_home", ograc_home)
                data_root = raw.get("data_root", data_root)
                user = raw.get("user", user)

                inst_cfg = raw.get("instance", {})
                cgroup_cfg = inst_cfg.get("cgroup", {})
                cgroup_memory_base = cgroup_cfg.get("memory_base", cgroup_memory_base)
                cgroup_memory_limit_gb = cgroup_cfg.get("memory_limit_gb", cgroup_memory_limit_gb)
                shm_cfg = inst_cfg.get("shm", {})
                shm_base = shm_cfg.get("base", shm_base)
                shm_prefix = shm_cfg.get("prefix", shm_prefix)

                timeout_overrides = raw.get("timeout", None)

                dss_cfg = raw.get("dss", {})
                dss_retry = dss_cfg.get("retry_times", dss_retry)
                dss_cmd_timeout = dss_cfg.get("cmd_timeout", dss_cmd_timeout)
                dss_init_timeout = dss_cfg.get("init_disk_timeout", dss_init_timeout)

            except (json.JSONDecodeError, OSError) as e:
                print(f"WARNING: Failed to load dss_config.json: {e}", file=sys.stderr)

        ograc_home = _resolve_required_ograc_home(ograc_home)
        data_root = _resolve_required_data_root(data_root)
        user = _resolve_required_ograc_user(user)

        instance = InstanceConfig(
            user=user,
            cgroup_memory_base=cgroup_memory_base,
            cgroup_memory_limit_gb=cgroup_memory_limit_gb,
            shm_base=shm_base,
            shm_prefix=shm_prefix,
        )
        paths = PathConfig(ograc_home=ograc_home, data_root=data_root, instance=instance)
        timeout = TimeoutConfig(timeout_overrides)
        dss = DssSpecificConfig(dss_retry, dss_cmd_timeout, dss_init_timeout)

        return paths, timeout, dss, user

    def get(self, key, default=""):
        return self.deploy.get(key, default)


_global_config = None


def get_config(dss_config_file=None, deploy_param_file=None, env_file=None):
    global _global_config
    if _global_config is None:
        _global_config = DssConfig(dss_config_file, deploy_param_file)
    return _global_config


def reset_config():
    global _global_config
    _global_config = None


class _LazyConfig:
    def __getattr__(self, name):
        return getattr(get_config(), name)


cfg = _LazyConfig()


def get_value(param):
    return get_config().get(param)


VG_CONFIG = {
    "vg1": "/dev/dss-disk1",
    "vg2": "/dev/dss-disk2",
    "vg3": "/dev/dss-disk3",
}

INST_CONFIG = {
    "INST_ID": "",
    "_LOG_LEVEL": 7,
    "_SHM_KEY": "",
    "STORAGE_MODE": "CLUSTER_RAID",
    "DSS_NODES_LIST": "",
    "LSNR_PATH": "",
    "_LOG_BACKUP_FILE_COUNT": "40",
    "_LOG_MAX_FILE_SIZE": "120M",
    "DSS_CM_SO_NAME": "libdsslock.so",
}


if __name__ == "__main__":
    if len(sys.argv) > 1:
        param = sys.argv[1]

        if param == "--shell-env":
            _cfg = get_config()
            print(f'OGRAC_HOME="{_cfg.paths.ograc_home}"')
            print(f'DSS_HOME="{_cfg.paths.dss_home}"')
            print(f'DSS_LOG_DIR="{_cfg.paths.dss_log_dir}"')
            print(f'OGRAC_USER="{_cfg.paths.instance.user}"')
        else:
            result = get_value(param)
            print(result)
