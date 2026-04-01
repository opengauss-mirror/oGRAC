#!/usr/bin/env python3
"""CMS unified configuration module."""

import os
import sys
import json

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
CMS_CONFIG_FILE = os.path.join(CUR_DIR, "cms_config.json")


class InstanceConfig:
    """Instance config: user as key for multi-user resource isolation."""

    def __init__(self, user="ograc",
                 cgroup_memory_base="/sys/fs/cgroup/memory",
                 cgroup_memory_limit_gb=10,
                 shm_base="/dev/shm",
                 shm_prefix="ograc"):
        self.user = user
        self.name = user

        self.cgroup_memory_base = cgroup_memory_base
        self.cgroup_memory_path = os.path.join(cgroup_memory_base, "cms", user)
        self.cgroup_memory_limit_gb = cgroup_memory_limit_gb

        self.shm_base = shm_base
        self.shm_prefix = shm_prefix
        self.shm_home = os.path.join(shm_base, user)
        self.shm_pattern = f"{shm_prefix}.[0-9]*"

    def __repr__(self):
        return (f"InstanceConfig(user={self.user!r}, "
                f"cgroup={self.cgroup_memory_path!r}, "
                f"mem_limit={self.cgroup_memory_limit_gb}GB, "
                f"shm_home={self.shm_home!r})")


class TimeoutConfig:
    """Operation timeout config. Set 0 for no limit. Unconfigured uses default."""

    _DEFAULTS = {
        "default":       1800,
        "install":       3600,
        "uninstall":     1800,
        "upgrade":       3600,
        "pre_install":   1800,
        "start":          600,
        "stop":           600,
        "check_status":   120,
        "backup":        7200,
    }

    def __init__(self, overrides=None):
        self._timeouts = dict(self._DEFAULTS)
        if overrides:
            for k, v in overrides.items():
                if not k.startswith("_"):
                    self._timeouts[k] = v

    def get(self, operation):
        """Get timeout seconds for operation. Returns int or None for no limit."""
        seconds = self._timeouts.get(operation, self._timeouts["default"])
        return None if seconds == 0 else int(seconds)

    def __repr__(self):
        return f"TimeoutConfig({self._timeouts})"


class PathConfig:
    """Derive all paths from ograc_home/data_root/instance for path decoupling."""

    def __init__(self, ograc_home="/opt/ograc", data_root="/mnt/dbdata",
                 instance=None):
        self.instance = instance or InstanceConfig()

        self.ograc_home = ograc_home
        self.data_root = data_root

        self.cms_home = os.path.join(ograc_home, "cms")
        self.ograc_app_home = os.path.join(ograc_home, "ograc")

        self.cms_cfg_dir = os.path.join(self.cms_home, "cfg")
        self.cms_ini = os.path.join(self.cms_cfg_dir, "cms.ini")
        self.cms_json = os.path.join(self.cms_cfg_dir, "cms.json")
        self.cms_enable_flag = os.path.join(self.cms_cfg_dir, "cms_enable")
        self.cms_service_dir = os.path.join(self.cms_home, "service")

        self.log_root = os.path.join(ograc_home, "log")
        self.cms_log_dir = os.path.join(self.log_root, "cms")
        self.cms_deploy_log = os.path.join(self.cms_log_dir, "cms_deploy.log")
        self.deploy_log_dir = os.path.join(self.log_root, "deploy")
        self.deploy_daemon_log = os.path.join(self.deploy_log_dir, "deploy_daemon.log")

        self.action_dir = os.path.join(ograc_home, "action")
        self.cms_scripts = os.path.join(self.action_dir, "cms")

        self.image_dir = os.path.join(ograc_home, "image")
        self.cms_pkg_dir = os.path.join(self.image_dir, "oGRAC-RUN-LINUX-64bit")
        self.rpm_flag = os.path.join(ograc_home, "installed_by_rpm")

        self.backup_dir = os.path.join(data_root, "backup")
        self.cms_old_config = os.path.join(self.backup_dir, "files", "cms.json")

        self.common_config_dir = os.path.join(ograc_home, "common", "config")
        self.primary_keystore = os.path.join(self.common_config_dir, "primary_keystore_bak.ks")
        self.standby_keystore = os.path.join(self.common_config_dir, "standby_keystore_bak.ks")
        self.certificates_dir = os.path.join(self.common_config_dir, "certificates")
        self.youmai_demo = os.path.join(ograc_home, "youmai_demo")

        self.versions_yml = os.path.join(ograc_home, "versions.yml")

        self.data_local = os.path.join(data_root, "local")
        self.data_remote = os.path.join(data_root, "remote")

        self.cgroup_memory_path = self.instance.cgroup_memory_path
        self.cgroup_default_mem_size_gb = self.instance.cgroup_memory_limit_gb

        self.shm_home = self.instance.shm_home

        self.cms_tmp_files = [
            os.path.join(self.cms_home, "cms_server.lck"),
            os.path.join(self.cms_home, "local"),
            os.path.join(self.cms_home, "gcc_backup"),
        ]

    def share_path(self, fs_name):
        """Share storage mount: /mnt/dbdata/remote/share_{fs}"""
        return os.path.join(self.data_remote, "share_" + fs_name)

    def archive_path(self, fs_name):
        """Archive storage mount: /mnt/dbdata/remote/archive_{fs}"""
        return os.path.join(self.data_remote, "archive_" + fs_name)

    def metadata_path(self, fs_name):
        """Metadata storage: /mnt/dbdata/remote/metadata_{fs}"""
        return os.path.join(self.data_remote, "metadata_" + fs_name)

    def gcc_home_path(self, deploy_mode, storage_share_fs):
        """Derive gcc_home from deploy mode."""
        return os.path.join(self.share_path(storage_share_fs), "gcc_home")

    def cms_gcc_bak_path(self, deploy_mode, storage_archive_fs):
        """Derive cms_gcc_bak from deploy mode."""
        return self.archive_path(storage_archive_fs)


class DeployConfig:
    """Load from root config load_deploy_params() + load_env_defaults()."""

    def __init__(self, env_file=None):
        self._params = dict(load_deploy_params())
        self._env = {}
        self._load_env()

    def _load_env(self):
        """Load user/group from root config."""
        self._env = load_env_defaults()

    def get(self, key, default=""):
        """Get deploy param from config_params_lun.json."""
        if key in ("ograc_user",):
            return self._env.get("ograc_user", default)
        if key in ("ograc_group",):
            return self._env.get("ograc_group", default)
        if key == "install_step":
            return self._get_cms_install_step(default)
        return self._params.get(key, default)

    def get_required(self, key):
        """Get required param, raise if missing."""
        value = self.get(key)
        if value == "" or value is None:
            raise ValueError(f"Required config key not found: {key}")
        return value

    def _get_cms_install_step(self, default=0):
        """Read install step from cms.json."""
        cms_json = os.path.join(
            _global_config.paths.cms_cfg_dir, "cms.json"
        ) if _global_config else "/opt/ograc/cms/cfg/cms.json"
        if os.path.exists(cms_json):
            try:
                with open(cms_json, "r", encoding="utf-8") as f:
                    return json.load(f).get("install_step", default)
            except (json.JSONDecodeError, OSError):
                pass
        return default

    @property
    def ograc_user(self):
        return self._env.get("ograc_user", "ograc")

    @property
    def ograc_group(self):
        return self._env.get("ograc_group", "ograc")

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
    def cluster_name(self):
        return self._params.get("cluster_name", "")

    @property
    def raw_params(self):
        return dict(self._params)


class CmsConfig:
    """CMS config entry - merge path config and deploy params. Global singleton."""

    def __init__(self, cms_config_file=None, deploy_param_file=None, env_file=None):
        self.paths, self.timeout = self._load_cms_config(cms_config_file or CMS_CONFIG_FILE)
        self.deploy = DeployConfig()

    @staticmethod
    def _load_cms_config(config_file):
        """Load path and timeout config from cms_config.json."""
        ograc_home = "/opt/ograc"
        data_root = "/mnt/dbdata"
        user = "ograc"

        cgroup_memory_base = "/sys/fs/cgroup/memory"
        cgroup_memory_limit_gb = 10
        shm_base = "/dev/shm"
        shm_prefix = "ograc"

        timeout_overrides = None

        if os.path.exists(config_file):
            try:
                with open(config_file, encoding="utf-8") as f:
                    raw = json.load(f)
                ograc_home = raw.get("ograc_home", ograc_home)
                data_root = raw.get("data_root", data_root)
                user = raw.get("user", user)

                mc = get_module_config()
                ograc_home = mc.get("ograc_home", ograc_home)
                data_root = mc.get("data_root", data_root)
                user = mc.get("user", user)

                inst_cfg = raw.get("instance", {})
                cgroup_cfg = inst_cfg.get("cgroup", {})
                cgroup_memory_base = cgroup_cfg.get("memory_base", cgroup_memory_base)
                cgroup_memory_limit_gb = cgroup_cfg.get("memory_limit_gb", cgroup_memory_limit_gb)
                shm_cfg = inst_cfg.get("shm", {})
                shm_base = shm_cfg.get("base", raw.get("shm_home", shm_base))
                shm_prefix = shm_cfg.get("prefix", shm_prefix)

                if "cgroup" in raw and "instance" not in raw:
                    old_cgroup = raw["cgroup"]
                    old_mem_path = old_cgroup.get("memory_path", "")
                    if old_mem_path:
                        if old_mem_path.endswith("/cms"):
                            cgroup_memory_base = old_mem_path[:-4]
                        else:
                            cgroup_memory_base = os.path.dirname(old_mem_path)
                    cgroup_memory_limit_gb = old_cgroup.get(
                        "default_mem_size_gb", cgroup_memory_limit_gb
                    )

                timeout_overrides = raw.get("timeout", None)

            except (json.JSONDecodeError, OSError) as e:
                print(f"WARNING: Failed to load cms_config.json: {e}", file=sys.stderr)
        else:
            mc = get_module_config()
            ograc_home = mc.get("ograc_home", ograc_home)
            data_root = mc.get("data_root", data_root)
            user = mc.get("user", user)

        ograc_home = os.environ.get("OGRAC_HOME", ograc_home)
        data_root = os.environ.get("OGRAC_DATA_ROOT", data_root)
        user = os.environ.get("OGRAC_USER", user)

        instance = InstanceConfig(
            user=user,
            cgroup_memory_base=cgroup_memory_base,
            cgroup_memory_limit_gb=cgroup_memory_limit_gb,
            shm_base=shm_base,
            shm_prefix=shm_prefix,
        )

        paths = PathConfig(
            ograc_home=ograc_home,
            data_root=data_root,
            instance=instance,
        )
        timeout = TimeoutConfig(timeout_overrides)

        return paths, timeout

    def get(self, key, default=""):
        """Get a deploy parameter by key."""
        return self.deploy.get(key, default)


_global_config = None


def get_config(cms_config_file=None, deploy_param_file=None, env_file=None):
    """Get or create global config singleton."""
    global _global_config
    if _global_config is None:
        _global_config = CmsConfig(cms_config_file, deploy_param_file)
    return _global_config


def reset_config():
    """Reset global config (for testing)."""
    global _global_config
    _global_config = None


class _LazyConfig:
    """Lazy init proxy, create CmsConfig on first access."""
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
            print(f'CMS_LOG_DIR="{_cfg.paths.cms_log_dir}"')
            print(f'OGRAC_USER="{_cfg.paths.instance.user}"')
            print(f'CGROUP_MEMORY_PATH="{_cfg.paths.instance.cgroup_memory_path}"')
            print(f'CGROUP_MEMORY_LIMIT_GB="{_cfg.paths.instance.cgroup_memory_limit_gb}"')
            print(f'SHM_HOME="{_cfg.paths.instance.shm_home}"')
            print(f'SHM_PATTERN="{_cfg.paths.instance.shm_pattern}"')
        else:
            result = get_value(param)
            print(result)
