"""
dbstor 统一配置管理模块（refactored）

路径解耦 + 可配置超时 + shell-env 输出
"""

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

CONFIG_FILE = os.path.join(CUR_DIR, "dbstor_config.json")
DEPLOY_PARAM_FILE = os.path.join(PKG_DIR, "config", "deploy_param.json")
VERSIONS_FILE = os.path.join(PKG_DIR, "versions.yml")
CONTAINER_DIR = os.path.join(PKG_DIR, "config", "container")
CONTAINER_DORADO_DIR = os.path.join(PKG_DIR, "config", "container_conf", "dorado_conf")


class TimeoutConfig:
    _DEFAULTS = {
        "default": 1800, "install": 1800, "start": 600, "stop": 300,
        "uninstall": 600, "check_status": 120, "backup": 600,
        "init_container": 1800, "pre_upgrade": 300, "upgrade_backup": 1800,
        "upgrade": 1800, "rollback": 1800, "update_config": 600,
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
                 dbstor_home="/opt/ograc/dbstor",
                 rpm_unpack_path="/opt/ograc/image/oGRAC-RUN-LINUX-64bit",
                 regress_data_dir="/home/regress/ograc_data"):
        self.ograc_home = ograc_home
        self.data_root = data_root
        self.dbstor_home = dbstor_home
        self.rpm_unpack_path = rpm_unpack_path
        self.regress_data_dir = regress_data_dir

        self.dbstor_scripts = posixpath.join(ograc_home, "action", "dbstor")
        self.log_dir = posixpath.join(ograc_home, "log", "dbstor")
        self.log_file = posixpath.join(self.log_dir, "install.log")
        self.uninstall_log = posixpath.join(self.log_dir, "uninstall.log")
        self.backup_log = posixpath.join(self.log_dir, "backup.log")
        self.backup_dir = posixpath.join(ograc_home, "backup")
        self.backup_files = posixpath.join(ograc_home, "backup", "files")
        self.image_dir = posixpath.join(ograc_home, "image")
        self.versions_yml = posixpath.join(ograc_home, "versions.yml")

        self.tools_dir = posixpath.join(dbstor_home, "tools")
        self.lib_dir = posixpath.join(dbstor_home, "lib")
        self.conf_dir = posixpath.join(dbstor_home, "conf")
        self.conf_dbs_dir = posixpath.join(dbstor_home, "conf", "dbs")
        self.conf_infra_config = posixpath.join(dbstor_home, "conf", "infra", "config")
        self.addons_dir = posixpath.join(dbstor_home, "add-ons")
        self.data_logs_run = posixpath.join(dbstor_home, "data", "logs", "run")

        self.dbstor_config_ini = posixpath.join(self.tools_dir, "dbstor_config.ini")
        self.client_cfg = posixpath.join(self.tools_dir, "client.cfg")

        self.client_test_dir = posixpath.join(rpm_unpack_path, "client_test")
        self.kmc_shared_dir = posixpath.join(rpm_unpack_path, "kmc_shared")
        self.addons_src_dir = posixpath.join(rpm_unpack_path, "add-ons")
        self.bin_dbstor = posixpath.join(rpm_unpack_path, "bin", "dbstor")
        self.cfg_dir = posixpath.join(rpm_unpack_path, "cfg")

        self.primary_keystore = posixpath.join(ograc_home, "common", "config", "primary_keystore.ks")
        self.standby_keystore = posixpath.join(ograc_home, "common", "config", "standby_keystore.ks")
        self.libkmc_so = posixpath.join(dbstor_home, "lib", "libkmcext.so")

        self.cms_dbstor_conf = posixpath.join(ograc_home, "cms", "dbstor", "conf", "dbs")
        self.cms_dbstor_ini = posixpath.join(ograc_home, "cms", "dbstor", "conf", "dbs", "dbstor_config.ini")

        self.local_dbstor_conf = posixpath.join(data_root, "local", "ograc", "tmp", "data", "dbstor", "conf", "dbs")
        self.local_dbstor_ini = posixpath.join(self.local_dbstor_conf, "dbstor_config.ini")

        self.container_dir = CONTAINER_DIR
        self.container_dorado_dir = CONTAINER_DORADO_DIR


def _load_deploy_param(path):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


class DbstorConfig:
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
        dbstor_home = raw.get("dbstor_home", posixpath.join(ograc_home, "dbstor"))
        rpm_path = raw.get("rpm_unpack_path", posixpath.join(ograc_home, "image", "oGRAC-RUN-LINUX-64bit"))
        regress_dir = raw.get("regress_data_dir", "/home/regress/ograc_data")

        env = load_env_defaults()
        self.user = env.get("ograc_user", raw.get("user", "ograc"))
        self.group = env.get("ograc_group", raw.get("group", "ograc"))
        self.common_group = env.get("ograc_common_group", f"{self.user}group")

        self.deploy_params = _load_deploy_param(DEPLOY_PARAM_FILE)
        self.paths = PathConfig(ograc_home=ograc_home, data_root=data_root,
                                dbstor_home=dbstor_home, rpm_unpack_path=rpm_path,
                                regress_data_dir=regress_dir)
        self.timeout = TimeoutConfig(raw.get("timeout"))
        self.shm_cleanup_patterns = raw.get("shm_cleanup_patterns", [
            "/dev/shm/ograc*", "/dev/shm/FDSA*",
            "/dev/shm/cpuinfo_shm", "/dev/shm/cputimeinfo_shm",
            "/dev/shm/diag_server_usr_lock",
        ])

    def get_deploy_param(self, key, default=""):
        return self.deploy_params.get(key, default)


_global_cfg = None


def get_config():
    global _global_cfg
    if _global_cfg is None:
        _global_cfg = DbstorConfig()
    return _global_cfg


class _LazyCfg:
    def __getattr__(self, name):
        return getattr(get_config(), name)


cfg = _LazyCfg()


def get_value(param):
    c = get_config()
    if param == "deploy_user":
        return c.user
    if param == "deploy_group":
        return c.group
    return c.get_deploy_param(param, "")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--shell-env":
        c = get_config()
        print(f'OGRAC_HOME="{c.paths.ograc_home}"')
        print(f'DBSTOR_USER="{c.user}"')
        print(f'DBSTOR_LOG_DIR="{c.paths.log_dir}"')
        print(f'DBSTOR_LOG_FILE="{c.paths.log_file}"')
        print(f'DBSTOR_HOME="{c.paths.dbstor_home}"')
    else:
        key = sys.argv[1] if len(sys.argv) > 1 else ""
        print(get_value(key))
