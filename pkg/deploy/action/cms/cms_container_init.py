#!/usr/bin/env python3
"""CMS container initialization."""

import os
import sys
import re
import shutil

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
if CUR_DIR not in sys.path:
    sys.path.insert(0, CUR_DIR)

from config import get_config
from log_config import get_logger
from utils import run_cmd

LOGGER = get_logger()


class CmsContainerInit:
    """Initialize CMS configuration for container deployment."""

    CLUSTER_CONFIG_NAME = "cluster.ini"
    CMS_CONFIG_NAME = "cms.ini"
    CMS_JSON_NAME = "cms.json"

    def __init__(self):
        self.cfg = get_config()
        self.paths = self.cfg.paths
        self.deploy = self.cfg.deploy

        self.config_path = self.paths.cms_cfg_dir
        self.cluster_ini = os.path.join(self.config_path, self.CLUSTER_CONFIG_NAME)
        self.cms_ini = os.path.join(self.config_path, self.CMS_CONFIG_NAME)

        self.node_id = int(self.deploy.node_id)
        self.cms_ip = self.deploy.get("cms_ip", "")
        self.cluster_id = self.deploy.get("cluster_id", "0")
        self.cluster_name = self.deploy.cluster_name
        self.deploy_mode = self.deploy.deploy_mode
        self.mes_ssl_switch = self.deploy.get("mes_ssl_switch", "False")
        self.ograc_user = self.deploy.ograc_user
        self.ograc_group = self.deploy.ograc_group
        self.storage_share_fs = self.deploy.storage_share_fs
        self.storage_archive_fs = self.deploy.storage_archive_fs
        self.cms_log = self.paths.cms_log_dir

        self.gcc_home = os.path.join(
            self.paths.ograc_home, "remote",
            f"share_{self.storage_share_fs}", "gcc_home"
        )
        self.cms_gcc_bak = os.path.join(
            self.paths.ograc_home, "remote",
            f"archive_{self.storage_share_fs}"
        )

        self.dorado_conf_path = os.path.join(
            CUR_DIR, "..", "..", "config", "container_conf", "dorado_conf"
        )
        self.cert_pass_file = os.path.join(self.dorado_conf_path, "certPass")


    @staticmethod
    def _ini_replace(filepath, key_pattern, new_value):
        """Replace matching key value in INI file. Format: KEY = VALUE -> KEY = new_value."""
        if not os.path.exists(filepath):
            LOGGER.warning(f"INI file not found: {filepath}")
            return False

        pattern = re.compile(rf"^({key_pattern}\s*=\s*).*$")
        modified = False
        lines = []
        with open(filepath, "r") as f:
            for line in f:
                m = pattern.match(line.rstrip("\n"))
                if m:
                    lines.append(f"{m.group(1)}{new_value}\n")
                    modified = True
                else:
                    lines.append(line)

        if modified:
            with open(filepath, "w") as f:
                f.writelines(lines)
        return modified


    def set_cms_ip(self):
        """Set CMS IP addresses in cluster.ini and cms.ini."""
        LOGGER.info("setting CMS IP addresses")
        parts = self.cms_ip.split(";") if self.cms_ip else []
        node_domain_0 = parts[0].strip() if len(parts) > 0 else ""
        node_domain_1 = parts[1].strip() if len(parts) > 1 else "127.0.0.1"

        self._ini_replace(self.cluster_ini, r"NODE_IP\[0\]", node_domain_0)
        self._ini_replace(self.cluster_ini, r"NODE_IP\[1\]", node_domain_1)
        self._ini_replace(self.cluster_ini, r"LSNR_NODE_IP\[0\]", node_domain_0)
        self._ini_replace(self.cluster_ini, r"LSNR_NODE_IP\[1\]", node_domain_1)

        if self.node_id == 0:
            self._ini_replace(self.cms_ini, r".*_IP", node_domain_0)
        else:
            self._ini_replace(self.cms_ini, r".*_IP", node_domain_1)

    def set_fs(self):
        """Set FS paths (GCC_HOME, GCC_DIR, etc.) in config files."""
        LOGGER.info("setting FS paths")
        gcc_home = self.gcc_home
        cms_gcc_bak = self.cms_gcc_bak

        self._ini_replace(self.cluster_ini, r"GCC_HOME", f"{gcc_home}/gcc_file")
        self._ini_replace(self.cms_ini, r"GCC_HOME", f"{gcc_home}/gcc_file")
        self._ini_replace(self.cms_ini, r".*_CMS_GCC_BAK", cms_gcc_bak)
        self._ini_replace(self.cms_ini, r"GCC_DIR", gcc_home)
        self._ini_replace(self.cms_ini, r"FS_NAME", self.storage_share_fs)

    def set_cms_cfg(self):
        """Set CMS config parameters (NODE_ID, CLUSTER_ID, SSL, etc.)."""
        LOGGER.info("setting CMS config parameters")
        self._ini_replace(self.cms_ini, r"NODE_ID", str(self.node_id))
        self._ini_replace(self.cluster_ini, r"NODE_ID", str(self.node_id))
        self._ini_replace(self.cms_ini, r"CLUSTER_ID", self.cluster_id)
        if self.mes_ssl_switch == "True":
            cert_password = ""
            if os.path.exists(self.cert_pass_file):
                with open(self.cert_pass_file, "r") as f:
                    cert_password = f.read().strip()
            self._ini_replace(
                self.cms_ini, r".*_CMS_MES_SSL_KEY_PWD", cert_password
            )
        else:
            self._ini_replace(self.cms_ini, r".*_CMS_MES_SSL_SWITCH", "False")

        if self.deploy_mode == "file":
            self._ini_replace(self.cms_ini, r"GCC_TYPE", "FILE")
            self._ini_replace(self.cms_ini, r".*_CMS_MES_PIPE_TYPE", "TCP")

        self._ini_replace(self.cms_ini, r"CMS_LOG", self.cms_log)


    def run(self):
        """Execute full container initialization."""
        LOGGER.info("===== Container Init Start =====")

        self.set_cms_ip()
        self.set_fs()
        self.set_cms_cfg()

        cms_json = os.path.join(self.config_path, self.CMS_JSON_NAME)
        if os.path.exists(cms_json):
            os.remove(cms_json)
            LOGGER.info(f"removed old {cms_json}")

        if self.node_id == 0:
            os.makedirs(self.gcc_home, mode=0o700, exist_ok=True)
            run_cmd(
                f"chown {self.ograc_user}:{self.ograc_group} -R {self.gcc_home}",
                f"failed to chown {self.gcc_home}",
            )
            LOGGER.info(f"created gcc_home: {self.gcc_home}")

        from cms_ctl import CmsCtl
        ctl = CmsCtl()
        ctl.init_container()

        LOGGER.info("===== Container Init Done =====")



def main():
    try:
        init = CmsContainerInit()
        init.run()
    except Exception as e:
        LOGGER.error(f"cms_container_init failed: {e}")
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
