#!/usr/bin/env python3
"""
oGRAC deploy orchestrator (runs as root).

Responsibilities:
  - Create/clean cgroup dirs and configure memory limits
  - Prepare permissions and log directories
  - Invoke ograc_ctl.py via run_python_as_user for business actions
"""

import os
import subprocess
import sys

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
BIND_CPU_SCRIPT = os.path.join(
    os.path.dirname(CUR_DIR), "ograc_common", "cpu_bind.py")
if CUR_DIR not in sys.path:
    sys.path.insert(0, CUR_DIR)

from config import get_config
from log_config import get_logger
from utils import ensure_dir, ensure_file, run_python_as_user, CommandError
from common.cgroup import (
    ensure_cgroup_dir, remove_cgroup_dir, attach_ogracd_pid,
    set_memory_limit_mb, list_ogracd_pids,
)
from common.ogracd_memcalc import calculate_reserved_mem_mb

LOG = get_logger()


class OgracDeploy:
    def __init__(self):
        self._cfg = get_config()
        self.paths = self._cfg.paths
        self.timeout = self._cfg.timeout
        self.deploy = self._cfg.deploy

        self.ograc_user = self.deploy.ograc_user
        self.ograc_group = self.deploy.ograc_group
        self.user_and_group = f"{self.ograc_user}:{self.ograc_group}"

    def _prepare_root_common(self):
        ensure_dir(self.paths.log_dir, 0o750, self.user_and_group)
        ensure_file(self.paths.log_file, 0o640, self.user_and_group)
        ensure_dir(self.paths.ograc_root, 0o750, self.user_and_group)

    def _run_ctl(self, action: str):
        self._prepare_root_common()
        script = os.path.join(CUR_DIR, "ograc_ctl.py")
        op_timeout = self.timeout.get(action)
        rc, out, err = run_python_as_user(
            script,
            [action],
            self.ograc_user,
            log_file=self.paths.log_file,
            timeout=op_timeout,
        )
        if rc != 0:
            raise CommandError(f"python3 ograc_ctl.py {action}", rc, out, err)
        for part in (out, err):
            if not part:
                continue
            for line in part.splitlines():
                if line.strip():
                    LOG.info(line)

    def _init_cpu_config(self):
        """Initialize CPU bind config template (runs as root).

        Equivalent to old storage_deploy/appctl.sh init_cpu_config():
            python3 bind_cpu_config.py 'init_config'
        """
        if not os.path.isfile(BIND_CPU_SCRIPT):
            LOG.warning("bind_cpu_config.py not found, skipping init_cpu_config")
            return
        LOG.info("Initializing CPU bind config")
        try:
            proc = subprocess.Popen(
                [sys.executable, BIND_CPU_SCRIPT, "init_config"],
                cwd=os.path.dirname(BIND_CPU_SCRIPT),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            out, err = proc.communicate(timeout=60)
            if proc.returncode != 0:
                LOG.warning("init_cpu_config failed (rc=%d): %s",
                            proc.returncode, err.decode("utf-8", errors="replace"))
        except Exception as e:
            LOG.warning("init_cpu_config exception: %s", e)

    def _update_cpu_config(self):
        """Calculate NUMA CPU binding and generate cpu_config.json (runs as ograc user).

        Equivalent to old storage_deploy/appctl.sh update_cpu_config():
            su -s /bin/bash - "${user}" -c "python3 bind_cpu_config.py"
        """
        if not os.path.isfile(BIND_CPU_SCRIPT):
            LOG.warning("bind_cpu_config.py not found, skipping update_cpu_config")
            return
        LOG.info("Updating CPU config")
        rc, out, err = run_python_as_user(
            BIND_CPU_SCRIPT, [], self.ograc_user,
            log_file=self.paths.log_file, timeout=120)
        if rc != 0:
            LOG.warning("update_cpu_config failed (rc=%d): %s", rc, err)

    def  action_pre_install(self):
        self._init_cpu_config()
        self._run_ctl("pre_install")

    def action_install(self):
        self._run_ctl("install")

    def action_uninstall(self):
        self._run_ctl("uninstall")
        remove_cgroup_dir()

    def action_start(self):
        ensure_cgroup_dir()
        self._update_cpu_config()
        self._run_ctl("start")
        pid_list = list_ogracd_pids(self.paths.d_data_path, self.ograc_user)
        if pid_list:
            attach_ogracd_pid(pid_list)

        limit_mb = self.paths.instance.memory_limit_mb
        if limit_mb <= 0:
            limit_mb = calculate_reserved_mem_mb(self.paths.ogracd_ini)
        if limit_mb > 0:
            set_memory_limit_mb(limit_mb)

    def action_stop(self):
        self._run_ctl("stop")

    def action_check_status(self):
        self._run_ctl("check_status")

    def action_backup(self):
        self._run_ctl("backup")

    def action_restore(self):
        self._run_ctl("restore")

    def action_init_container(self):
        self._run_ctl("init_container")

    def action_post_upgrade(self):
        self._run_ctl("post_upgrade")

    def _noop(self, name):
        LOG.info(f"Action {name}: no-op (not yet migrated)")

    def action_pre_upgrade(self):
        self._noop("pre_upgrade")

    def action_upgrade_backup(self):
        self._noop("upgrade_backup")

    def action_upgrade(self):
        self._noop("upgrade")

    def action_rollback(self):
        self._noop("rollback")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 ograc_deploy.py <action>", file=sys.stderr)
        sys.exit(1)

    action = sys.argv[1]
    deployer = OgracDeploy()

    action_map = {
        "pre_install": deployer.action_pre_install,
        "install": deployer.action_install,
        "uninstall": deployer.action_uninstall,
        "start": deployer.action_start,
        "stop": deployer.action_stop,
        "check_status": deployer.action_check_status,
        "backup": deployer.action_backup,
        "restore": deployer.action_restore,
        "init_container": deployer.action_init_container,
        "post_upgrade": deployer.action_post_upgrade,
        "pre_upgrade": deployer.action_pre_upgrade,
        "upgrade_backup": deployer.action_upgrade_backup,
        "upgrade": deployer.action_upgrade,
        "rollback": deployer.action_rollback,
    }

    fn = action_map.get(action)
    if fn is None:
        print(f"Unknown or not implemented action: {action}", file=sys.stderr)
        sys.exit(1)

    try:
        fn()
    except CommandError as e:
        details = "\n".join(part for part in (e.stdout.strip(), e.stderr.strip()) if part)
        if details:
            LOG.error("%s\n%s", str(e), details)
        else:
            LOG.error(str(e))
        sys.exit(1)
    except Exception as e:
        LOG.error(str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()

