#!/usr/bin/env python3
"""
CMS startup module -- full replacement for start_cms.sh + cms_start2.sh.

Actions:
  - install_cms:    GCC preparation + node registration (first install)
  - start_cms:      Start CMS server background process
  - init_container: Container-mode GCC preparation + node registration
  - start2 / stop2 / check2: Daily start/stop shortcuts (replaces cms_start2.sh)

Usage:
  1. Module import: from cms_startup import CmsStartup; CmsStartup(cfg).start_cms()
  2. CLI:           python3 cms_startup.py --process start_cms
  3. CLI (v2):      python3 cms_startup.py -start / -stop / -check
"""

import os
import sys
import argparse
import time
import subprocess
import tempfile

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
if CUR_DIR not in sys.path:
    sys.path.insert(0, CUR_DIR)

from config import get_config
from log_config import get_logger
from utils import exec_popen, run_cmd, CommandError, ensure_file

LOGGER = get_logger()



class ClusterConfig:
    """
    Parse cluster.ini (INI-style with shell array syntax).

    Example format:
        NODE_ID = 0
        CLUSTER_SIZE = 2
        NODE_IP[0] = 192.168.1.1
        NODE_IP[1] = 192.168.1.2
        CMS_PORT[0] = 14587
    """

    def __init__(self, config_file):
        self._scalars = {}
        self._arrays = {}
        self._parse(config_file)

    def _parse(self, path):
        if not os.path.exists(path):
            raise FileNotFoundError(f"Cluster config not found: {path}")
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip()
                if "[" in key and key.endswith("]"):
                    base = key[:key.index("[")]
                    idx = int(key[key.index("[") + 1:-1])
                    self._arrays.setdefault(base, {})[idx] = value
                else:
                    self._scalars[key] = value

    def get(self, key, default=""):
        return self._scalars.get(key, default)

    def get_int(self, key, default=0):
        v = self._scalars.get(key)
        return int(v) if v is not None else default

    def get_array(self, key):
        """Return ordered list sorted by index."""
        arr = self._arrays.get(key, {})
        if not arr:
            return []
        max_idx = max(arr.keys())
        return [arr.get(i, "") for i in range(max_idx + 1)]

    def __contains__(self, key):
        return key in self._scalars or key in self._arrays



class CmsStartup:
    """
    CMS startup operations -- full replacement for start_cms.sh logic.

    Loads cluster.ini and deploy configuration on init.
    """

    def __init__(self, cluster_config_path=None, is_rerun=False):
        self._cfg = get_config()
        self.paths = self._cfg.paths

        self.deploy_mode = self._cfg.deploy.deploy_mode
        self.ograc_in_container = self._cfg.deploy.ograc_in_container
        self.metadata_fs = self._cfg.deploy.storage_metadata_fs

        self.cms_home = os.environ.get("CMS_HOME", self.paths.cms_home)
        self.cms_install_path = os.path.join(self.cms_home, "service")

        if cluster_config_path is None:
            cluster_config_path = os.path.join(self.cms_home, "cfg", "cluster.ini")
        if not os.path.exists(cluster_config_path):
            raise FileNotFoundError(f"Cluster config not found: {cluster_config_path}")
        self.cluster = ClusterConfig(cluster_config_path)

        self.node_id = self.cluster.get_int("NODE_ID", 0)
        self.cluster_size = self.cluster.get_int("CLUSTER_SIZE", 2)
        self.node_ips = self.cluster.get_array("NODE_IP")
        self.cms_ports = self.cluster.get_array("CMS_PORT")
        self.gcc_home = self.cluster.get("GCC_HOME", "")
        self.status_log = self.cluster.get(
            "STATUS_LOG",
            os.path.join(self.paths.cms_log_dir, "CmsStatus.log"),
        )
        self.use_gss = self.cluster.get("USE_GSS", "False")

        self.is_rerun = is_rerun
        self.cms_bin = os.path.join(self.cms_install_path, "bin", "cms")

        self._ensure_ld_library_path()

    def _ensure_ld_library_path(self):
        """Inject cms lib/add-ons into LD_LIBRARY_PATH for all child processes."""
        lib_dir = os.path.join(self.cms_install_path, "lib")
        addons_dir = os.path.join(self.cms_install_path, "add-ons")
        existing = os.environ.get("LD_LIBRARY_PATH", "")
        needed = [lib_dir, addons_dir]
        parts = existing.split(":") if existing else []
        for d in needed:
            if d not in parts:
                parts.insert(0, d)
        os.environ["LD_LIBRARY_PATH"] = ":".join(parts)

    def _cms_cmd(self, subcmd):
        """Execute a cms command (sources .bashrc for environment)."""
        full = f"source ~/.bashrc 2>/dev/null; {self.cms_bin} {subcmd}"
        return run_cmd(full, f"cms {subcmd} failed")

    def _wait_for_success(self, attempts, check_fn, label=""):
        """Wait for check_fn to return True, up to `attempts` seconds."""
        for i in range(attempts):
            if check_fn():
                return True
            time.sleep(1)
        LOGGER.warning(f"wait_for_success timeout ({attempts}s): {label}")
        if not check_fn():
            raise TimeoutError(f"Timed out waiting for: {label}")
        return True


    def prepare_gcc(self):
        """Prepare GCC storage (node0 only).

        In DSS mode gcc_home is a block device (e.g. /dev/gcc-disk); dd/chmod
        requires root and is handled by cms_deploy.py._prepare_gcc_device().
        Here we only handle file-mode preparation and gcc -reset.
        """
        if self.is_rerun:
            return
        if self.node_id != 0:
            return

        youmai_demo = self.paths.youmai_demo

        if self.deploy_mode == "file" or os.path.exists(youmai_demo):
            LOGGER.info(f"zeroing {self.gcc_home} on node {self.node_id}")
            run_cmd(f"rm -rf {self.gcc_home}*")
            run_cmd(f"dd if=/dev/zero of={self.gcc_home} bs=1M count=1024")
            run_cmd(f"chmod 600 {self.gcc_home}")
        elif self.deploy_mode == "dss":
            LOGGER.info(f"GCC device {self.gcc_home} prepared by root, skipping dd/chmod")

        self._cms_cmd("gcc -reset -f")
        LOGGER.info("prepare_gcc done")


    def _check_node_in_cluster(self):
        """Check if the current node is registered in the cluster."""
        ret, stdout, _ = exec_popen(
            f"source ~/.bashrc 2>/dev/null; {self.cms_bin} node -list"
        )
        expected = f"node{self.node_id}"
        if expected not in stdout:
            raise RuntimeError(f"CHECK NODE LIST FAILED: {expected} not found")

    def _check_res_in_cluster(self):
        """Check if resources are registered in the cluster."""
        ret, stdout, _ = exec_popen(
            f"source ~/.bashrc 2>/dev/null; {self.cms_bin} res -list"
        )
        if "cluster" not in stdout and "db" not in stdout:
            raise RuntimeError("CHECK RES LIST FAILED")

    def _is_node1_joined(self):
        ret, stdout, stderr = exec_popen(
            f"source ~/.bashrc 2>/dev/null; {self.cms_bin} node -list"
        )
        if ret != 0:
            LOGGER.warning("cms node -list failed (rc=%d): %s %s", ret, stdout, stderr)
        return ret == 0 and "node1" in stdout

    def _is_gcc_initialized(self):
        ret, stdout, _ = exec_popen(
            f"source ~/.bashrc 2>/dev/null; {self.cms_bin} gccmark -check"
        )
        return "success" in stdout

    def _wait_for_node1(self):
        LOGGER.info("waiting for node1 to join cluster...")
        self._wait_for_success(180, self._is_node1_joined, "node1 join")

    def setup_cms(self):
        """Register nodes and resources."""
        LOGGER.info(f"===== setup cms node {self.node_id} =====")
        youmai_demo = self.paths.youmai_demo

        if self.node_id == 0:
            if self.cluster_size == 1:
                self._cms_cmd(
                    f"node -add 0 node0 127.0.0.1 {self.cms_ports[0] if self.cms_ports else '14587'}"
                )
            else:
                for i in range(self.cluster_size):
                    ip = self.node_ips[i] if i < len(self.node_ips) else "127.0.0.1"
                    port = self.cms_ports[i] if i < len(self.cms_ports) else "14587"
                    self._cms_cmd(f"node -add {i} node{i} {ip} {port}")

            self._cms_cmd(
                f'res -add db -type db -attr "script={self.cms_install_path}/bin/cluster.sh"'
            )

        elif self.node_id == 1:
            self._wait_for_node1()

        self._check_node_in_cluster()
        self._cms_cmd("node -list")
        self._check_res_in_cluster()
        self._cms_cmd("res -list")
        LOGGER.info(f"===== setup cms node {self.node_id} done =====")


    def install_cms(self):
        """Install CMS (GCC preparation + node registration)."""
        LOGGER.info("===== install_cms =====")
        if self.ograc_in_container == "0":
            self.prepare_gcc()
            self.setup_cms()
        LOGGER.info("===== install_cms done =====")

    def start_cms(self):
        """Start the CMS server process."""
        LOGGER.info(f"===== start cms node {self.node_id} =====")
        self._check_node_in_cluster()
        self._cms_cmd("node -list")
        self._check_res_in_cluster()
        self._cms_cmd("res -list")

        ensure_file(self.status_log, 0o640)

        if self.deploy_mode == "dss":
            dss_home = os.environ.get("DSS_HOME", "")
            if dss_home:
                os.environ["LD_LIBRARY_PATH"] = (
                    f"{dss_home}/lib:" + os.environ.get("LD_LIBRARY_PATH", "")
                )
                run_cmd(f"source ~/.bashrc 2>/dev/null; dsscmd reghl -D {dss_home}")

        run_cmd(
            f"source ~/.bashrc 2>/dev/null; "
            f"nohup {self.cms_bin} server -start >> {self.status_log} 2>&1 &",
            "START CMS FAILED",
        )
        self._cms_cmd("stat -server")
        LOGGER.info(f"===== start cms node {self.node_id} done =====")

    def init_container(self):
        """Container initialization."""
        self.prepare_gcc()
        self.setup_cms()
        flag = os.path.join(self.cms_home, "cfg", "container_flag")
        with open(flag, "w"):
            pass


    def _wait_for_cms_server_ready(self, pid, timeout=120):
        """Wait for cms server to become ready."""
        for _ in range(timeout):
            ret, current_pid, _ = exec_popen(
                "ps -ef | grep 'cms server -start' | grep -v grep | awk '{print $2}' | head -n 1"
            )
            current_pid = current_pid.strip()
            if not current_pid:
                time.sleep(1)
                continue
            if current_pid != str(pid):
                raise RuntimeError(
                    f"Another cms [{current_pid}] running, expected [{pid}]"
                )
            ret, stdout, _ = exec_popen(
                f"source ~/.bashrc 2>/dev/null; "
                f"cms stat -server {self.node_id} | grep -q TRUE && echo OK"
            )
            if "OK" in stdout:
                return True
            time.sleep(1)
        raise TimeoutError("cms server start timeout")

    def start2(self):
        """Daily start (replaces cms_start2.sh -start)."""
        LOGGER.info(f"===== start2 cms node {self.node_id} =====")
        run_cmd(
            f"source ~/.bashrc 2>/dev/null; "
            f"nohup cms server -start >> {self.status_log} 2>&1 &"
        )
        time.sleep(0.5)
        ret, pid_str, _ = exec_popen(
            "ps -ef | grep 'cms server -start' | grep -v grep | awk '{print $2}' | head -n 1"
        )
        pid = pid_str.strip()
        LOGGER.info(f"cms server starting, pid={pid}")
        self._wait_for_cms_server_ready(pid)

        ret, stdout, _ = exec_popen(
            "source ~/.bashrc 2>/dev/null; cms res -list | grep dss | wc -l"
        )
        if stdout.strip() != "0":
            LOGGER.info(f"starting dss on node {self.node_id}")
            run_cmd(
                f"source ~/.bashrc 2>/dev/null; cms res -start dss -node {self.node_id}"
            )
        LOGGER.info(f"starting db on node {self.node_id}")
        run_cmd(
            f"source ~/.bashrc 2>/dev/null; cms res -start db -node {self.node_id}"
        )
        LOGGER.info("===== start2 done =====")

    def stop2(self):
        """Daily stop (replaces cms_start2.sh -stop)."""
        LOGGER.info("===== stop2 cms =====")
        user = os.environ.get("USER", "")
        ret, count, _ = exec_popen(
            f"ps -u {user} | grep cms | grep -v grep | wc -l"
        )
        count = int(count.strip()) if count.strip().isdigit() else 0
        if count == 0:
            raise RuntimeError("CMS process not found")
        run_cmd(
            f"ps -u {user} | grep cms | grep -v grep | awk '{{print $1}}' | xargs kill -9",
            "failed to kill cms",
        )
        LOGGER.info("===== stop2 done =====")

    def check2(self):
        """Check CMS process count (replaces cms_start2.sh -check)."""
        user = os.environ.get("USER", "")
        ret, stdout, _ = exec_popen(
            f"ps -fu {user} | grep 'cms server -start' | grep -vE '(grep|defunct)' | wc -l"
        )
        count = int(stdout.strip()) if stdout.strip().isdigit() else 0
        return count



def main():
    parser = argparse.ArgumentParser(description="CMS Startup Operations")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-P", "--process",
                       choices=["install_cms", "start_cms", "init_container"],
                       help="Process type (replaces start_cms.sh -P)")
    group.add_argument("-start", action="store_true", help="Start CMS (v2)")
    group.add_argument("-stop", action="store_true", help="Stop CMS (v2)")
    group.add_argument("-check", action="store_true", help="Check CMS (v2)")
    parser.add_argument("-R", "--rerun", action="store_true", help="Rerun mode")
    args = parser.parse_args()

    try:
        home = os.path.expanduser("~")
        bashrc = os.path.join(home, ".bashrc")
        if os.path.exists(bashrc):
            ret, env_out, _ = exec_popen(
                f"source {bashrc} 2>/dev/null && env"
            )
            if ret == 0:
                for line in env_out.split("\n"):
                    if "=" in line:
                        k, _, v = line.partition("=")
                        os.environ[k] = v

        startup = CmsStartup(is_rerun=args.rerun)

        if args.process == "install_cms":
            startup.install_cms()
        elif args.process == "start_cms":
            startup.start_cms()
        elif args.process == "init_container":
            _cfg = get_config()
            version_path = _cfg.paths.metadata_path(_cfg.deploy.storage_metadata_fs)
            version_file = os.path.join(version_path, "versions.yml")
            if not os.path.exists(version_file):
                startup.init_container()
            else:
                LOGGER.info("versions.yml exists, skip init_container")
        elif args.start:
            startup.start2()
        elif args.stop:
            startup.stop2()
        elif args.check:
            count = startup.check2()
            sys.exit(count)

    except Exception as e:
        LOGGER.error(f"cms_startup failed: {e}")
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
