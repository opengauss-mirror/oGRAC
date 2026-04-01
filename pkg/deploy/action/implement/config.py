#!/usr/bin/env python3
"""implement unified configuration module."""

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
VERSIONS_FILE = os.path.join(PKG_DIR, "versions.yml")


class PathConfig:
    def __init__(self, ograc_home="/opt/ograc", data_root="/mnt/dbdata"):
        self.ograc_home = ograc_home
        self.data_root = data_root

        self.versions_yml = posixpath.join(ograc_home, "versions.yml")

        self.certificates_dir = posixpath.join(ograc_home, "common", "config", "certificates")
        self.ca_crt = posixpath.join(self.certificates_dir, "ca.crt")
        self.mes_crt = posixpath.join(self.certificates_dir, "mes.crt")
        self.mes_key = posixpath.join(self.certificates_dir, "mes.key")
        self.mes_crl = posixpath.join(self.certificates_dir, "mes.crl")
        self.mes_pass = posixpath.join(self.certificates_dir, "mes.pass")

        self.primary_keystore = posixpath.join(ograc_home, "common", "config", "primary_keystore_bak.ks")
        self.standby_keystore = posixpath.join(ograc_home, "common", "config", "standby_keystore_bak.ks")
        self.dbstor_lib = posixpath.join(ograc_home, "dbstor", "lib")

        self.ogracd_ini = posixpath.join(data_root, "local", "ograc", "tmp", "data", "cfg", "ogracd.ini")
        self.cms_ini = posixpath.join(ograc_home, "cms", "cfg", "cms.ini")

        self.update_ograc_passwd_py = posixpath.join(ograc_home, "action", "implement", "update_ograc_passwd.py")

        self.deploy_param_json = posixpath.join(ograc_home, "config", "deploy_param.json")


def _load_deploy_param(path):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


class ImplementConfig:
    def __init__(self):
        ograc_home = os.environ.get("OGRAC_HOME", "/opt/ograc")
        data_root = os.environ.get("OGRAC_DATA_ROOT", "/mnt/dbdata")

        env = load_env_defaults()
        self.user = env.get("ograc_user", "ograc")
        self.group = env.get("ograc_group", "ograc")

        self.deploy_params = _load_deploy_param(DEPLOY_PARAM_FILE)
        self.paths = PathConfig(ograc_home=ograc_home, data_root=data_root)

    def get_deploy_param(self, key, default=""):
        return self.deploy_params.get(key, default)


_global_cfg = None


def get_config():
    global _global_cfg
    if _global_cfg is None:
        _global_cfg = ImplementConfig()
    return _global_cfg


class _LazyCfg:
    def __getattr__(self, name):
        return getattr(get_config(), name)


cfg = _LazyCfg()
