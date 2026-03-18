#!/usr/bin/env python3
"""docker unified configuration module."""
import json
import os
import posixpath
import sys

import importlib.util
_ACTION_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
_root_config_path = os.path.join(_ACTION_DIR, "config.py")
_spec = importlib.util.spec_from_file_location("_action_config", _root_config_path)
_action_config = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_action_config)
load_env_defaults = _action_config.load_env_defaults

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
PKG_DIR = os.path.abspath(os.path.join(CUR_DIR, "../.."))
DEPLOY_PARAM_FILE = os.path.join(PKG_DIR, "config", "deploy_param.json")
INSTALL_CONFIG_FILE = os.path.join(PKG_DIR, "action", "ograc", "install_config.json")


class PathConfig:
    """Single source for all container paths, no scattered hardcode."""

    def __init__(self, ograc_home="/opt/ograc", data_root="/mnt/dbdata"):
        self.ograc_home = ograc_home
        self.data_root = data_root

        self.config_dir = posixpath.join(ograc_home, "config")
        self.deploy_param_json = posixpath.join(self.config_dir, "deploy_param.json")
        self.versions_yml = posixpath.join(ograc_home, "versions.yml")
        self.healthy_file = posixpath.join(ograc_home, "healthy")
        self.readiness_file = posixpath.join(ograc_home, "readiness")
        self.stop_enable_file = posixpath.join(ograc_home, "stop.enable")

        self.common_config_dir = posixpath.join(ograc_home, "common", "config")
        self.primary_keystore = posixpath.join(self.common_config_dir, "primary_keystore_bak.ks")
        self.standby_keystore = posixpath.join(self.common_config_dir, "standby_keystore_bak.ks")

        self.dbstor_lib = posixpath.join(ograc_home, "dbstor", "lib")
        self.dbstor_tools = posixpath.join(ograc_home, "dbstor", "tools")

        self.log_dir = posixpath.join(ograc_home, "log")
        self.deploy_log_dir = posixpath.join(self.log_dir, "deploy")
        self.deploy_log = posixpath.join(self.deploy_log_dir, "deploy.log")
        self.dbstor_unify_flag = posixpath.join(self.deploy_log_dir, ".dbstor_unify_flag")

        self.remote_data = posixpath.join(data_root, "remote")
        self.local_data = posixpath.join(data_root, "local", "ograc", "tmp", "data")
        self.ogsql_ini = posixpath.join(self.local_data, "cfg", "ogsql.ini")

        self.og_om_dir = posixpath.join(ograc_home, "og_om")
        self.ograc_server_bin = posixpath.join(ograc_home, "ograc", "server", "bin")
        self.ograc_cfg_dir = posixpath.join(ograc_home, "ograc", "cfg")
        self.ograc_exporter_dir = posixpath.join(ograc_home, "ograc_exporter")
        self.certificates_dir = posixpath.join(self.common_config_dir, "certificates")
        self.cms_cfg_dir = posixpath.join(ograc_home, "cms", "cfg")
        self.cms_container_flag = posixpath.join(self.cms_cfg_dir, "container_flag")
        self.cms_enable = posixpath.join(self.cms_cfg_dir, "cms_enable")
        self.cms_res_disable = posixpath.join(ograc_home, "cms", "res_disable")
        self.image_dir = posixpath.join(ograc_home, "image", "oGRAC-RUN-LINUX-64bit")
        self.action_dir = posixpath.join(ograc_home, "action")
        self.common_script_dir = posixpath.join(ograc_home, "common", "script")
        self.logs_handler_execute = posixpath.join(self.common_script_dir, "logs_handler", "execute.py")
        self.ograc_service_sh = posixpath.join(self.common_script_dir, "ograc_service.sh")
        self.single_flag = posixpath.join(self.ograc_cfg_dir, "single_flag")
        self.start_status_json = posixpath.join(self.ograc_cfg_dir, "start_status.json")

        self.container_conf_dir = posixpath.join(self.config_dir, "container_conf")
        self.kube_config = posixpath.join(self.config_dir, ".kube", "config")
        self.kube_config_src = "/root/.kube/config"
        self.logicrep_home = "/opt/software/tools/logicrep"
        self.user_file = posixpath.join(self.logicrep_home, "create_user.json")

        self.numa_info_path = "/root/.kube/NUMA-INFO/numa-pod.json"
        self.pod_record_file = "/home/mfdb_core/POD-RECORD/ograc-pod-record.csv"

        self.cpuset_cpus = "/sys/fs/cgroup/cpuset/cpuset.cpus"

        self.systable_home = posixpath.join(ograc_home, "ograc", "server", "admin", "scripts", "rollUpgrade")
        self.initdb_sql = posixpath.join(ograc_home, "ograc", "server", "admin", "scripts", "initdb.sql")

    def metadata_fs_path(self, storage_metadata_fs):
        return posixpath.join(self.remote_data, f"metadata_{storage_metadata_fs}")

    def share_fs_path(self, storage_share_fs):
        return posixpath.join(self.remote_data, f"share_{storage_share_fs}")

    def archive_fs_path(self, storage_archive_fs):
        return posixpath.join(self.remote_data, f"archive_{storage_archive_fs}")

    def storage_fs_path(self, storage_dbstor_fs):
        return posixpath.join(self.remote_data, f"storage_{storage_dbstor_fs}")

    def gcc_file_path(self, storage_share_fs):
        return posixpath.join(self.share_fs_path(storage_share_fs), "gcc_home", "gcc_file")

    def dorado_conf_path(self, config_dir=None):
        """Container-conf dorado_conf path (based on pkg config)."""
        base = config_dir or os.path.join(PKG_DIR, "config")
        return os.path.join(base, "container_conf", "dorado_conf")



def _load_deploy_param():
    """Load deploy_param.json from package config dir."""
    if not os.path.exists(DEPLOY_PARAM_FILE):
        return {}
    try:
        with open(DEPLOY_PARAM_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _load_install_config():
    if not os.path.exists(INSTALL_CONFIG_FILE):
        return {}
    try:
        with open(INSTALL_CONFIG_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}



class DockerConfig:
    """Aggregates paths, user info, deploy_param values."""

    def __init__(self, ograc_home="/opt/ograc", data_root="/mnt/dbdata"):
        self.paths = PathConfig(ograc_home=ograc_home, data_root=data_root)
        self._deploy_params = _load_deploy_param()
        self._env = load_env_defaults()
        self._install_config = _load_install_config()

    @property
    def ograc_user(self):
        return self._env.get("ograc_user", "ograc")

    @property
    def ograc_group(self):
        return self._env.get("ograc_group", "ograc")

    @property
    def ograc_common_group(self):
        return self._env.get("ograc_common_group", f"{self.ograc_user}group")

    @property
    def deploy_params(self):
        return self._deploy_params

    @property
    def install_config(self):
        return self._install_config

    def get(self, key, default=""):
        """Dot-notation lookup into deploy_param.json."""
        if key in ("ograc_user", "deploy_user"):
            return self.ograc_user
        if key in ("ograc_group", "deploy_group"):
            return self.ograc_group
        if key == "M_RUNING_MODE":
            return self._install_config.get("M_RUNING_MODE", default)
        keys = key.split(".")
        value = self._deploy_params
        try:
            for k in keys:
                if value == "":
                    return value
                value = value.get(k, "")
            return value
        except (KeyError, TypeError, AttributeError):
            return default



_global_cfg = None


def get_config():
    """Return the singleton DockerConfig."""
    global _global_cfg
    if _global_cfg is None:
        _global_cfg = DockerConfig()
    return _global_cfg


class _LazyCfg:
    """Module-level lazy proxy so callers can ``from config import cfg``."""
    def __getattr__(self, name):
        return getattr(get_config(), name)


cfg = _LazyCfg()



def get_value(param):
    """Compatible helper: ``get_value("node_id")`` etc."""
    return get_config().get(param)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--shell-env":
        _cfg = get_config()
        print(f'OGRAC_HOME="{_cfg.paths.ograc_home}"')
        print(f'DEPLOY_USER="{_cfg.ograc_user}"')
        print(f'DEPLOY_GROUP="{_cfg.ograc_group}"')
    else:
        key = sys.argv[1] if len(sys.argv) > 1 else ""
        print(get_value(key))
