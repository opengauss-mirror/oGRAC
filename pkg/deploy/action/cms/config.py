"""
CMS 统一配置管理模块

功能：
  1. 路径解耦：所有路径从 cms_config.json 读取，支持自定义安装目录
  2. 统一配置读取：一次性加载 config_params_lun.json，替代 100+ 次 python3 调用
  3. 替代原 get_config_info.py，提供更清晰的 API

用法：
  from config import cfg
  print(cfg.cms_home)           # 路径属性
  print(cfg.get("deploy_mode")) # 部署参数
"""

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
    """
    实例配置 —— 以 user（系统用户名）为主键，管理多用户部署时的资源隔离。

    所有用户一视同仁，统一按 user 做子目录分割：
      - cgroup:  /sys/fs/cgroup/memory/cms/{user}
      - shm:     /dev/shm/{user}/
    """

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
    """
    操作超时配置 —— 按操作类型分别设置超时秒数。

    低配机器可在 cms_config.json 中调大对应值；设为 0 表示不限超时（None）。
    未配置的操作使用 default 值。
    """

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
        """
        获取指定操作的超时秒数。

        Args:
            operation: 操作名称，如 "install", "start", "check_status"

        Returns:
            超时秒数(int)，或 None（表示不限超时）
        """
        seconds = self._timeouts.get(operation, self._timeouts["default"])
        return None if seconds == 0 else int(seconds)

    def __repr__(self):
        return f"TimeoutConfig({self._timeouts})"


class PathConfig:
    """
    从 ograc_home / data_root / instance 推导全部路径，实现路径解耦。
    所有原来硬编码 /opt/ograc 的地方，都从这里获取。
    """

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

        self.backup_dir = os.path.join(ograc_home, "backup")
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
        """共享存储挂载点: /mnt/dbdata/remote/share_{fs}"""
        return os.path.join(self.data_remote, "share_" + fs_name)

    def archive_path(self, fs_name):
        """归档存储挂载点: /mnt/dbdata/remote/archive_{fs}"""
        return os.path.join(self.data_remote, "archive_" + fs_name)

    def metadata_path(self, fs_name):
        """元数据存储: /mnt/dbdata/remote/metadata_{fs}"""
        return os.path.join(self.data_remote, "metadata_" + fs_name)

    def gcc_home_path(self, deploy_mode, storage_share_fs):
        """根据部署模式推导 gcc_home"""
        return os.path.join(self.share_path(storage_share_fs), "gcc_home")

    def cms_gcc_bak_path(self, deploy_mode, storage_archive_fs):
        """根据部署模式推导 cms_gcc_bak"""
        return self.archive_path(storage_archive_fs)


class DeployConfig:
    """
    统一从根 config 的 load_deploy_params() 读取 config_params_lun.json + load_env_defaults()。
    """

    def __init__(self, env_file=None):
        self._params = dict(load_deploy_params())
        self._env = {}
        self._load_env()

    def _load_env(self):
        """从 root config 加载用户/组信息（user 推导 group/common_group）"""
        self._env = load_env_defaults()

    def get(self, key, default=""):
        """获取部署参数（来自 config_params_lun.json）"""
        if key == "deploy_user":
            return self._env.get("ograc_user", default)
        if key == "deploy_group":
            return self._env.get("ograc_group", default)
        if key == "install_step":
            return self._get_cms_install_step(default)
        return self._params.get(key, default)

    def get_required(self, key):
        """获取必要参数，不存在则抛出异常"""
        value = self.get(key)
        if value == "" or value is None:
            raise ValueError(f"Required config key not found: {key}")
        return value

    def _get_cms_install_step(self, default=0):
        """从 cms.json 读取安装步骤"""
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
    """
    CMS 配置入口 - 合并路径配置和部署参数。
    全局单例，所有模块通过 from config import cfg 使用。
    """

    def __init__(self, cms_config_file=None, deploy_param_file=None, env_file=None):
        self.paths, self.timeout = self._load_cms_config(cms_config_file or CMS_CONFIG_FILE)
        self.deploy = DeployConfig()

    @staticmethod
    def _load_cms_config(config_file):
        """从 cms_config.json 加载路径配置和超时配置"""
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
        """兼容旧版 get_value() 接口"""
        return self.deploy.get(key, default)


_global_config = None


def get_config(cms_config_file=None, deploy_param_file=None, env_file=None):
    """获取或创建全局配置单例"""
    global _global_config
    if _global_config is None:
        _global_config = CmsConfig(cms_config_file, deploy_param_file)
    return _global_config


def reset_config():
    """重置全局配置（用于测试）"""
    global _global_config
    _global_config = None


class _LazyConfig:
    """延迟初始化代理，首次访问时才创建 CmsConfig"""
    def __getattr__(self, name):
        return getattr(get_config(), name)


cfg = _LazyConfig()


def get_value(param):
    """
    向后兼容旧版 get_config_info.py 的 get_value() 函数。
    新代码请使用 cfg.get() 或 cfg.deploy.xxx。
    """
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
