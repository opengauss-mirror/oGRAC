#!/usr/bin/env python3
"""DSS deploy orchestrator (runs as root). Called by appctl.sh."""

import os
import subprocess
import sys

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
if CUR_DIR not in sys.path:
    sys.path.insert(0, CUR_DIR)

from config import get_config
from log_config import get_logger

LOG = get_logger()


def _exec(cmd, timeout=300):
    """Execute shell command, reclaim process on timeout."""
    proc = subprocess.Popen(
        ["bash", "-c", cmd],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        out_b, err_b = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        return -1, "", f"Timeout after {timeout}s"
    return (
        proc.returncode,
        out_b.decode(errors="replace").strip(),
        err_b.decode(errors="replace").strip(),
    )


def _run_cmd(cmd, error_msg=""):
    ret, stdout, stderr = _exec(cmd)
    if ret != 0:
        msg = error_msg or f"Command failed: {cmd}"
        raise RuntimeError(f"{msg}: {stdout} {stderr}")
    return stdout


class DssDeploy:
    """DSS deploy orchestrator."""

    def __init__(self):
        self._cfg = get_config()
        self.paths = self._cfg.paths
        self.deploy = self._cfg.deploy
        self.timeout = self._cfg.timeout

        self.ograc_user = self.deploy.ograc_user
        self.ograc_group = self.deploy.ograc_group
        self.user_and_group = f"{self.ograc_user}:{self.ograc_group}"


    def _prepare_dirs(self):
        """Create log and install dirs, set permissions."""
        log_dir = self.paths.dss_log_dir
        os.makedirs(log_dir, mode=0o750, exist_ok=True)
        log_file = self.paths.dss_deploy_log
        if not os.path.exists(log_file):
            open(log_file, "a").close()
            os.chmod(log_file, 0o640)
        _run_cmd(
            f"chmod -R 750 {log_dir} && chown -hR {self.user_and_group} {log_dir}",
            "failed to prepare log dir",
        )

        dss_home = self.paths.dss_home
        os.makedirs(dss_home, mode=0o750, exist_ok=True)
        _run_cmd(
            f"chown -hR {self.user_and_group} {dss_home}",
            "failed to chown dss_home",
        )

    def _set_permissions(self):
        """Set install dir and script permissions."""
        dss_home = self.paths.dss_home
        if os.path.isdir(os.path.join(dss_home, "bin")):
            _run_cmd(f"chmod 500 {dss_home}/bin/* 2>/dev/null || true")
            _run_cmd(f"chown -hR {self.user_and_group} {dss_home}")

        _run_cmd(f"chown -hR {self.user_and_group} {CUR_DIR}/*")
        _run_cmd(f"chown root:root {CUR_DIR}/appctl.sh")

        self._config_perctrl_caps()

    def _config_perctrl_caps(self):
        """Set perctrl capabilities as root (must be after chown)."""
        perctrl = os.path.join(self.paths.dss_home, "bin", "perctrl")
        if not os.path.isfile(perctrl):
            LOG.warning("perctrl not found at %s, skip setcap", perctrl)
            return
        _run_cmd(
            f"setcap cap_sys_admin,cap_sys_rawio+ep {perctrl}",
            "failed to setcap perctrl",
        )
        LOG.info("perctrl capabilities configured")

    def _copy_scripts(self):
        """Copy DSS scripts to install dir (skip if src == dst)."""
        scripts_dir = self.paths.dss_scripts_dir
        if os.path.realpath(CUR_DIR) == os.path.realpath(scripts_dir):
            LOG.info("DSS scripts already in install path, skip copy")
            return
        LOG.info(f"Copying scripts from {CUR_DIR} to {scripts_dir}")
        if os.path.isdir(scripts_dir):
            import shutil
            shutil.rmtree(scripts_dir)
        os.makedirs(scripts_dir, mode=0o755, exist_ok=True)
        _run_cmd(f"cp -arf {CUR_DIR}/* {scripts_dir}/")


    def _run_ctl(self, action, mode=""):
        """Invoke dss_ctl.py as business user."""
        self._prepare_dirs()
        self._set_permissions()

        script = os.path.join(CUR_DIR, "dss_ctl.py")
        args = f"--action={action}"
        if mode:
            args += f" --mode={mode}"

        cmd = f'su -s /bin/bash - {self.ograc_user} -c "python3 -B {script} {args}"'
        op_timeout = self.timeout.get(action) or 1800
        LOG.info(f"Running dss_ctl.py {action} as {self.ograc_user}")
        ret, stdout, stderr = _exec(cmd, timeout=op_timeout)
        if stdout:
            LOG.info(stdout)
        if ret != 0:
            raise RuntimeError(
                f"dss_ctl.py {action} failed (rc={ret}): {stdout} {stderr}"
            )
        return stdout


    def action_pre_install(self):
        self._run_ctl("pre_install")

    def _ensure_user_profile_writable(self):
        """Ensure ograc user .bashrc exists and is writable (fix ownership as root)."""
        import pwd as _pwd
        try:
            home = _pwd.getpwnam(self.ograc_user).pw_dir
        except KeyError:
            LOG.warning("User %s not found, skip profile fix", self.ograc_user)
            return
        bashrc = os.path.join(home, ".bashrc")
        if not os.path.exists(bashrc):
            open(bashrc, "w").close()
        _run_cmd(f"chown {self.user_and_group} {bashrc}", "failed to chown .bashrc")
        os.chmod(bashrc, 0o644)

    def _prepare_source(self):
        """Copy DSS bin/lib to install dir as root."""
        import shutil as _shutil
        source_dir = self.paths.source_dir
        dss_home = self.paths.dss_home
        for subdir in ("bin", "lib"):
            src = os.path.join(source_dir, subdir)
            dst = os.path.join(dss_home, subdir)
            if not os.path.isdir(src):
                LOG.warning("DSS source %s not found, skip", src)
                continue
            if os.path.exists(dst):
                _shutil.rmtree(dst)
            _shutil.copytree(src, dst)
        _run_cmd(f"chown -R {self.user_and_group} {dss_home}")
        LOG.info("DSS bin/lib copied to %s", dss_home)

    def action_install(self, mode=""):
        if not os.path.isfile(self.paths.rpm_flag):
            self._copy_scripts()
            self._prepare_source()
        self._ensure_user_profile_writable()
        self._run_ctl("install", mode)

    def action_start(self):
        self._run_ctl("start")

    def action_stop(self):
        self._run_ctl("stop")

    def action_check_status(self):
        self._run_ctl("check_status")

    def action_uninstall(self, mode=""):
        self._run_ctl("uninstall", mode)

    def action_backup(self):
        self._run_ctl("backup")

    def action_restore(self):
        LOG.info("restore: no-op for DSS")

    def action_pre_upgrade(self):
        self._run_ctl("pre_upgrade")

    def action_upgrade_backup(self):
        self._run_ctl("upgrade_backup")

    def action_upgrade(self):
        self._run_ctl("upgrade")

    def action_rollback(self):
        self._run_ctl("rollback")



def main():
    if len(sys.argv) < 2:
        print(
            "Usage: python3 dss_deploy.py <action> [args...]\n"
            "Actions: start, stop, pre_install, install, uninstall, check_status,\n"
            "         backup, pre_upgrade, upgrade_backup, upgrade, rollback",
            file=sys.stderr,
        )
        sys.exit(1)

    action = sys.argv[1]
    args = sys.argv[2:]

    deployer = DssDeploy()

    try:
        if action == "install":
            mode = args[0] if args else ""
            deployer.action_install(mode)
        elif action == "uninstall":
            mode = args[0] if args else ""
            deployer.action_uninstall(mode)
        elif action in ("start", "stop", "pre_install", "check_status",
                        "backup", "restore", "pre_upgrade", "upgrade_backup",
                        "upgrade", "rollback"):
            getattr(deployer, f"action_{action}")()
        else:
            print(f"Unknown action: {action}", file=sys.stderr)
            sys.exit(1)

    except Exception as e:
        LOG.error(f"Action '{action}' failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
