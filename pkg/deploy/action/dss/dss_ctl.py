#!/usr/bin/env python3
"""DSS core controller."""

import argparse
import datetime
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import time

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
if CUR_DIR not in sys.path:
    sys.path.insert(0, CUR_DIR)

from config import get_config, VG_CONFIG, INST_CONFIG
from log_config import get_logger

LOG = get_logger()



def _copytree_compat(src, dst, **kwargs):
    """shutil.copytree compat: Python < 3.8 lacks dirs_exist_ok."""
    kwargs.pop("dirs_exist_ok", None)
    if os.path.isdir(dst):
        for item in os.listdir(src):
            s = os.path.join(src, item)
            d = os.path.join(dst, item)
            if os.path.isdir(s):
                _copytree_compat(s, d, **kwargs)
            else:
                shutil.copy2(s, d)
    else:
        shutil.copytree(src, dst, **kwargs)


def exec_popen(cmd, timeout=60):
    """Execute a shell command."""
    pobj = subprocess.Popen(
        ["bash"], shell=False,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        stdout_bytes, stderr_bytes = pobj.communicate(
            input=(cmd + os.linesep).encode(), timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        pobj.kill()
        pobj.communicate()
        return -1, "", f"Timeout after {timeout}s"
    stdout = stdout_bytes.decode().rstrip(os.linesep)
    stderr = stderr_bytes.decode().rstrip(os.linesep)
    return pobj.returncode, stdout, stderr


class ComOpt:
    """INI file read/write utility."""

    @staticmethod
    def write_ini(file_path, contents, split="="):
        content_lines = [f"{key}{split}{value}" for key, value in contents.items()]
        modes = stat.S_IWRITE | stat.S_IRUSR
        flags = os.O_WRONLY | os.O_TRUNC | os.O_CREAT
        with os.fdopen(os.open(file_path, flags, modes), 'w', encoding='utf-8') as f:
            f.write("\n".join(content_lines))
        os.chmod(file_path, 0o640)

    @staticmethod
    def read_ini(file_path):
        with open(file_path, 'r', encoding="utf-8") as f:
            return f.read()



class DssCtl:
    """
    DSS core controller.
    Runs as business user (e.g. ograc). All paths from config.py.
    """

    CAP_WIO = "CAP_SYS_RAWIO"
    CAP_ADM = "CAP_SYS_ADMIN"

    def __init__(self):
        cfg = get_config()
        self.paths = cfg.paths
        self.dss_cfg = cfg.dss
        self.deploy = cfg.deploy

        self.dss_home = self.paths.dss_home
        self.dss_cfg_dir = self.paths.dss_cfg_dir
        self.dss_inst_ini = self.paths.dss_inst_ini
        self.dss_vg_ini = self.paths.dss_vg_ini
        self.dss_log_dir = self.paths.dss_log_dir
        self.cms_service_dir = self.paths.cms_service_dir
        self.source_dir = self.paths.source_dir
        self.backup_dir = self.paths.backup_dir
        self.scripts_dir = self.paths.dss_scripts_dir
        self.control_script = self.paths.dss_control_script
        self.install_file = self.paths.install_config
        self.rpm_flag = self.paths.rpm_flag
        self.run_log = self.paths.dss_run_log

        self.node_id = self.deploy.node_id
        self.cms_ip = self.deploy.cms_ip
        self.dss_port = self.deploy.dss_port
        self.mes_ssl_switch = self.deploy.mes_ssl_switch

        self.cmd_timeout = self.dss_cfg.cmd_timeout
        self.init_disk_timeout = self.dss_cfg.init_disk_timeout

        self.begin_time = None


    def modify_env(self, action="add"):
        """Modify user env vars (DSS_HOME, LD_LIBRARY_PATH, PATH).
        Write after shebang/comment lines in .bashrc for non-interactive shells."""
        import pwd as _pwd
        try:
            home_dir = _pwd.getpwnam(self.deploy.ograc_user).pw_dir
        except KeyError:
            home_dir = os.path.expanduser('~')
        bashrc = os.path.join(home_dir, '.bashrc')

        lines = []
        if os.path.isfile(bashrc):
            with open(bashrc, 'r') as f:
                lines = f.readlines()

        env_lines = [
            f"export DSS_HOME={self.dss_home}\n",
            f"export LD_LIBRARY_PATH={self.dss_home}/lib:$LD_LIBRARY_PATH\n",
            f"export PATH={self.dss_home}/bin:$PATH\n",
        ]

        for env_line in env_lines:
            while env_line in lines:
                lines.remove(env_line)

        if action == "add":
            insert_pos = 0
            for i, line in enumerate(lines):
                stripped = line.strip()
                if stripped == "" or stripped.startswith("#") or stripped.startswith("#!/"):
                    insert_pos = i + 1
                else:
                    break
            for j, env_line in enumerate(env_lines):
                lines.insert(insert_pos + j, env_line)

        modes = stat.S_IWUSR | stat.S_IRUSR
        flags = os.O_WRONLY | os.O_TRUNC | os.O_CREAT
        with os.fdopen(os.open(bashrc, flags, modes), 'w', encoding='utf-8') as f:
            f.writelines(lines)


    def _dss_cmd(self, subcmd, timeout=None):
        """Execute DSS command (auto source bashrc)."""
        timeout = timeout or self.cmd_timeout
        full = f"source ~/.bashrc 2>/dev/null; {subcmd}"
        ret, stdout, stderr = exec_popen(full, timeout=timeout)
        return ret, stdout, stderr

    def _cms_library_path(self):
        ograc_home = self.paths.ograc_home
        return ":".join([
            f"{self.cms_service_dir}/lib",
            f"{self.cms_service_dir}/add-ons",
            f"{ograc_home}/ograc/server/lib",
            f"{ograc_home}/ograc/server/add-ons",
        ])

    def _cms_exec(self, args):
        cms_bin = os.path.join(self.cms_service_dir, "bin", "cms")
        lib_path = self._cms_library_path()
        loader_candidates = (
            "/lib64/ld-linux-x86-64.so.2",
            "/lib/ld-linux-aarch64.so.1",
            "/lib64/ld-linux-aarch64.so.1",
        )
        for loader in loader_candidates:
            if os.path.isfile(loader):
                return (f'"{loader}" --library-path "{lib_path}:${{LD_LIBRARY_PATH:-}}" '
                        f'"{cms_bin}" {args}')
        return f'export LD_LIBRARY_PATH="{lib_path}:$LD_LIBRARY_PATH"; "{cms_bin}" {args}'

    def _kill_pids(self, cmd, label="process"):
        ret, stdout, stderr = exec_popen(cmd, timeout=self.cmd_timeout)
        if ret:
            LOG.info(f"{label} is offline: {stdout}{stderr}")
            return
        if not stdout or not stdout.strip():
            LOG.info(f"{label}: no PID found")
            return
        LOG.info(f"{label} pid(s): [{stdout.strip()}]")
        for pid in stdout.strip().splitlines():
            pid = pid.strip()
            if pid and pid.isdigit():
                exec_popen(f"kill -9 {pid}", timeout=self.cmd_timeout)
                LOG.info(f"Sent SIGKILL to {pid}")


    def prepare_dss_disk(self):
        """Initialize disk (node 0 only)."""
        if self.node_id != "0":
            LOG.info(f"No need to init lun for node [{self.node_id}]")
            return
        LOG.info("Start to init lun")
        for key, value in VG_CONFIG.items():
            cmd = f"dd if=/dev/zero of={value} bs=2048 count=1000 conv=notrunc"
            ret, stdout, stderr = exec_popen(cmd, timeout=self.init_disk_timeout)
            if ret:
                raise RuntimeError(f"Init lun failed: {cmd} → {stdout}{stderr}")
            LOG.info(f"Init lun success: {cmd}")
        LOG.info("All LUNs initialized")

    def dss_cmd_add_vg(self):
        """Create volume group (node 0 only)."""
        if self.node_id != "0":
            LOG.info(f"No need to create VG for node [{self.node_id}]")
            return
        LOG.info("Start to exec dsscmd cv")
        for key, value in VG_CONFIG.items():
            cmd = f"dsscmd cv -g {key} -v {value}"
            ret, stdout, stderr = self._dss_cmd(cmd)
            if ret:
                raise RuntimeError(f"dsscmd cv failed: {cmd} → {stdout}{stderr}")
        LOG.info("All VGs created")

    def reghl_dss_disk(self):
        """Register disk."""
        LOG.info("Start to reghl disk")
        if self.check_is_reg():
            self.kick_node()
        cmd = f"dsscmd reghl -D {self.dss_home}"
        ret, stdout, stderr = self._dss_cmd(cmd)
        if ret:
            raise RuntimeError(f"reghl failed: {stdout}{stderr}")
        LOG.info("reghl disk success")

    def check_is_reg(self):
        cmd = f"dsscmd inq_reg -i {self.node_id} -D {self.dss_home}"
        ret, stdout, stderr = self._dss_cmd(cmd)
        if ret:
            LOG.error(f"inq_reg failed: {stdout}{stderr}")
        return "is registered" in str(stdout)

    def kick_node(self):
        LOG.info("Start to kick node")
        cmd = f"dsscmd unreghl -D {self.dss_home}"
        ret, stdout, stderr = self._dss_cmd(cmd)
        if ret:
            raise RuntimeError(f"kick node failed: {stdout}{stderr}")
        LOG.info("kick node success")


    def prepare_cfg(self):
        """Generate DSS config files."""
        os.makedirs(self.dss_home, exist_ok=True)
        os.makedirs(self.dss_cfg_dir, exist_ok=True)

        ComOpt.write_ini(self.dss_vg_ini, VG_CONFIG, split=":")

        if not str(self.dss_port).isdigit():
            raise RuntimeError(f"Invalid dss_port for DSS cluster: {self.dss_port}")
        ips = self.cms_ip.split(";")
        if len(ips) < 2:
            raise RuntimeError(f"Invalid cms_ip for DSS cluster: {self.cms_ip}")
        INST_CONFIG["INST_ID"] = self.node_id
        INST_CONFIG["_SHM_KEY"] = str(self.deploy.dss_shm_key)
        INST_CONFIG["DSS_NODES_LIST"] = f"0:{ips[0]}:{self.dss_port},1:{ips[1]}:{self.dss_port}"
        INST_CONFIG["LSNR_PATH"] = self.dss_home
        INST_CONFIG["LOG_HOME"] = self.dss_log_dir
        INST_CONFIG["STORAGE_MODE"] = "SHARE_DISK"
        ComOpt.write_ini(self.dss_inst_ini, INST_CONFIG)

    def prepare_source(self):
        """Verify DSS bin/lib in place (copied by dss_deploy.py as root)."""
        for subdir in ("bin", "lib"):
            d = os.path.join(self.dss_home, subdir)
            if not os.path.isdir(d):
                raise RuntimeError(
                    f"{d} not found. dss_deploy.py should have copied it.")
        LOG.info("DSS bin/lib verified at %s", self.dss_home)


    def cms_add_dss_res(self):
        """Register DSS resource with CMS."""
        os.chmod(self.control_script, 0o700)
        dst = os.path.join(self.dss_home, "dss_contrl.sh")
        shutil.copyfile(self.control_script, dst)
        os.chmod(dst, 0o700)

        if self.node_id == "0":
            LOG.info("Start to add dss res")
            cmd = self._cms_exec(f'res -add dss -type dss -attr "script={dst}"')
            ret, stdout, stderr = self._dss_cmd(cmd)
            if ret:
                raise RuntimeError(f"Failed to add dss res: {stdout}{stderr}")
            LOG.info("dss res added")
        LOG.info("dss control script copied")

    def config_perctrl_permission(self):
        """Verify perctrl capabilities (set by dss_deploy.py as root)."""
        path = f"{self.dss_home}/bin/perctrl"
        if not os.path.isfile(path):
            LOG.warning("perctrl not found at %s", path)
            return
        ret, stdout, _ = exec_popen(f"getcap {path}", timeout=self.cmd_timeout)
        if "cap_sys_rawio" not in stdout:
            LOG.warning("perctrl capabilities may not be set: %s", stdout)
        else:
            LOG.info("perctrl capabilities verified: %s", stdout.strip())


    def wait_dss_instance_started(self):
        """Poll log until DSS starts."""
        LOG.info("Waiting for dss_instance to start...")
        timeout = 60
        while timeout > 0:
            time.sleep(5)
            timeout -= 5
            if not os.path.exists(self.run_log):
                continue
            with open(self.run_log, 'r', errors='ignore') as f:
                text = f.read()
            succ_pat = re.compile(
                r'.*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*?DSS SERVER STARTED.*?',
                re.IGNORECASE,
            )
            fail_pat = re.compile(
                r'.*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*?dss failed to startup.*?',
                re.IGNORECASE,
            )
            succ_ts = re.findall(succ_pat, text)
            fail_ts = re.findall(fail_pat, text)

            if succ_ts and max(succ_ts) >= self.begin_time:
                LOG.info("DSS server started successfully")
                return
            if fail_ts and max(fail_ts) >= self.begin_time:
                raise RuntimeError("DSS server start failed")

        raise RuntimeError("Start dss server timeout")

    def clean_ipc(self):
        """Clean all System V IPC resources (shm, sem, msg) for DSS user."""
        LOG.info("Cleaning IPC resources for current DSS instance")
        try:
            uid = pwd.getpwnam(self.deploy.ograc_user).pw_uid
        except KeyError:
            LOG.warning("Skip IPC cleanup because user %s does not exist", self.deploy.ograc_user)
            return

        user = self.deploy.ograc_user
        ipc_types = [
            ("-m", "ipcrm -m", "shm", 5),
            ("-s", "ipcrm -s", "sem", -1),
            ("-q", "ipcrm -q", "msg", -1),
        ]
        for list_flag, rm_prefix, label, nattch_col in ipc_types:
            ret, stdout, stderr = exec_popen(f"ipcs {list_flag}", timeout=self.cmd_timeout)
            if ret:
                LOG.warning("Failed to list %s: %s%s", label, stdout, stderr)
                continue
            for line in stdout.splitlines():
                parts = line.split()
                if len(parts) < 3 or not parts[1].isdigit():
                    continue
                owner = parts[2]
                if owner not in (str(uid), user):
                    continue
                if nattch_col >= 0 and len(parts) > nattch_col and parts[nattch_col] != "0":
                    continue
                ipc_id = parts[1]
                ret, _, err = exec_popen(f"{rm_prefix} {ipc_id}", timeout=self.cmd_timeout)
                if ret:
                    LOG.warning("Failed to remove %s %s: %s", label, ipc_id, err)
                else:
                    LOG.info("Removed %s segment %s", label, ipc_id)

    def clean_shm(self):
        """Backward-compat alias."""
        self.clean_ipc()

    def clean_soft(self):
        """Clean software (bin/lib/cfg, keep logs)."""
        LOG.info("Cleaning software")
        for subdir in ("lib", "bin"):
            path = os.path.join(self.dss_home, subdir)
            if os.path.exists(path):
                shutil.rmtree(path)
        if os.path.exists(self.dss_cfg_dir):
            shutil.rmtree(self.dss_cfg_dir)
        LOG.info("Software cleaned")


    def pre_install(self, *args):
        LOG.info("===== pre_install start =====")
        LOG.info("===== pre_install done =====")

    def install(self, *args):
        LOG.info("===== install start =====")
        with open(self.install_file, encoding="utf-8") as f:
            info = json.load(f)
            dss_install_type = info.get("install_type", "")
            dss_vg_list = info.get("dss_vg_list", "")

        self._specify_dss_vg(dss_vg_list)
        LOG.info(f"dss_install_type is {dss_install_type}")

        self.modify_env(action="add")
        self.prepare_cfg()
        if not os.path.exists(self.rpm_flag):
            self.prepare_source()
        self.cms_add_dss_res()
        self.config_perctrl_permission()

        if dss_install_type != "reserve":
            self.prepare_dss_disk()
            self.reghl_dss_disk()
            self.dss_cmd_add_vg()

        LOG.info("===== install done =====")

    def _specify_dss_vg(self, dss_vg_list):
        """Update VG config from deploy params."""
        LOG.info("Specifying VG from user configuration")
        if dss_vg_list:
            for vg_name, vg_path in dss_vg_list.items():
                VG_CONFIG[vg_name] = vg_path
        LOG.info("VG configuration updated")

    def start(self, *args):
        LOG.info("===== start dss server =====")
        if self.check_status():
            return
        self.reghl_dss_disk()
        self.begin_time = str(datetime.datetime.now()).split(".")[0]
        cmd = f"source ~/.bashrc && nohup dssserver -D {self.dss_home} &"
        subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.wait_dss_instance_started()
        if self.check_status():
            LOG.info("dss server started")
        else:
            raise RuntimeError("Failed to start dss server")

    def stop(self, *args):
        LOG.info("===== stop dss server =====")
        escaped = re.escape(self.dss_home)
        self._kill_pids(
            f"ps -eo pid=,args= | grep '[d]ssserver' | grep -E '{escaped}' | awk '{{print $1}}'",
            label="dssserver")
        for _ in range(10):
            if not self.check_status():
                break
            import time
            time.sleep(1)
        else:
            LOG.warning("dssserver still alive after kill, trying pidof")
            self._kill_pids("pidof dssserver", label="dssserver(pidof)")
        LOG.info("dssserver stopped")
        self._kill_pids(
            f"ps -eo pid=,args= | grep '[p]erctrl' | grep -E '{escaped}' | awk '{{print $1}}'",
            label="perctrl")
        LOG.info("perctrl stopped")
        self.clean_shm()

    def check_status(self, *args):
        cmd = f"ps -ef | grep dssserver | grep -v grep | grep {self.dss_home}"
        _, stdout, _ = exec_popen(cmd, timeout=self.cmd_timeout)
        if stdout:
            LOG.info(f"dssserver is online: {stdout}")
            return True
        LOG.info("dssserver is offline")
        return False

    def _cms_del_dss_res(self):
        """Remove DSS resource from CMS (node 0 only)."""
        if self.node_id != "0":
            return
        LOG.info("Removing dss resource from CMS")
        cmd = self._cms_exec("res -del dss")
        ret, stdout, stderr = self._dss_cmd(cmd)
        if ret:
            LOG.warning("Failed to del dss res (may already be removed): %s%s", stdout, stderr)
        else:
            LOG.info("dss res removed from CMS")

    def _unreghl_dss_disk(self):
        """Unregister disk."""
        if not self.check_is_reg():
            LOG.info("Disk not registered, skip unreghl")
            return
        LOG.info("Unregistering disk")
        cmd = f"dsscmd unreghl -D {self.dss_home}"
        ret, stdout, stderr = self._dss_cmd(cmd)
        if ret:
            LOG.warning("unreghl failed (non-fatal): %s%s", stdout, stderr)
        else:
            LOG.info("unreghl disk success")

    def uninstall(self, *args):
        LOG.info("===== uninstall start =====")
        self._cms_del_dss_res()
        self._unreghl_dss_disk()
        self.modify_env(action="delete")
        self.clean_shm()
        if not os.path.exists(self.rpm_flag):
            self.clean_soft()
        LOG.info("===== uninstall done =====")

    def backup(self, *args):
        LOG.info("===== backup start =====")
        os.makedirs(self.backup_dir, exist_ok=True)
        _copytree_compat(self.dss_cfg_dir, self.backup_dir,
                         symlinks=False, copy_function=shutil.copy2)
        scripts_bak = os.path.join(self.backup_dir, "scripts")
        os.makedirs(scripts_bak, exist_ok=True)
        _copytree_compat(self.scripts_dir, scripts_bak)
        LOG.info("===== backup done =====")

    def upgrade_backup(self, *args):
        LOG.info("===== upgrade_backup start =====")
        LOG.info("===== upgrade_backup done =====")

    def upgrade(self, *args):
        LOG.info("===== upgrade start =====")
        LOG.info("===== upgrade done =====")

    def rollback(self, *args):
        LOG.info("===== rollback start =====")
        LOG.info("===== rollback done =====")

    def pre_upgrade(self, *args):
        LOG.info("===== pre_upgrade start =====")
        LOG.info("===== pre_upgrade done =====")



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--action", type=str, required=True,
                        choices=["install", "uninstall", "start", "stop", "pre_install",
                                 "upgrade", "rollback", "pre_upgrade", "check_status",
                                 "upgrade_backup", "backup"])
    parser.add_argument("--mode", required=False, default="")
    args = parser.parse_args()

    ctl = DssCtl()
    getattr(ctl, args.action)(args.mode)


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        LOG.error(str(err))
        sys.exit(1)
