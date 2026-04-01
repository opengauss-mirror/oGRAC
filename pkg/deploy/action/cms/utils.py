#!/usr/bin/env python3
"""CMS shared utilities."""

import os
import sys
import re
import subprocess
import signal
import time
import glob as glob_mod
from log_config import get_logger

LOGGER = get_logger()



class CommandError(Exception):
    """Exception when command execution fails."""
    def __init__(self, cmd, returncode, stdout="", stderr=""):
        self.cmd = cmd
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        super().__init__(
            f"Command failed (rc={returncode}): {cmd}\n"
            f"stdout: {stdout}\nstderr: {stderr}"
        )


def exec_popen(cmd, timeout=1800):
    """Execute shell command via subprocess, return (returncode, stdout, stderr)."""
    pobj = subprocess.Popen(
        ["bash"],
        shell=False,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        stdout_bytes, stderr_bytes = pobj.communicate(
            input=(cmd + os.linesep).encode(),
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        pobj.kill()
        pobj.communicate()
        return -1, "Time Out.", f"Command timed out after {timeout}s"

    stdout = stdout_bytes.decode().rstrip(os.linesep)
    stderr = stderr_bytes.decode().rstrip(os.linesep)
    return pobj.returncode, stdout, stderr


def run_cmd(cmd, error_msg="Command failed", force_uninstall=None):
    """Execute command and check return code; raise CommandError on failure unless force_uninstall=='force'."""
    ret_code, stdout, stderr = exec_popen(cmd)
    if ret_code:
        output = stdout + stderr
        LOGGER.error("%s.\ncommand: %s.\noutput: %s" % (error_msg, cmd, output))
        if force_uninstall != "force":
            raise CommandError(cmd, ret_code, stdout, stderr)
    return stdout


def run_as_user(cmd, user, log_file=None):
    """Execute shell command as specified user. Returns (returncode, stdout, stderr)."""
    if log_file:
        full_cmd = f'su -s /bin/bash - {user} -c "{cmd} >> {log_file} 2>&1"'
    else:
        full_cmd = f'su -s /bin/bash - {user} -c "{cmd}"'
    return exec_popen(full_cmd)


def run_python_as_user(script, args, user, log_file=None, cwd=None, timeout=1800):
    """Execute Python script as specified user via subprocess with uid/gid switch. Returns (returncode, stdout, stderr)."""
    import pwd

    pw = pwd.getpwnam(user)
    uid, gid, home = pw.pw_uid, pw.pw_gid, pw.pw_dir

    def _demote():
        """preexec_fn: switch to target user before child exec."""
        os.setgid(gid)
        os.initgroups(user, gid)
        os.setuid(uid)

    env = os.environ.copy()
    env.update({"HOME": home, "USER": user, "LOGNAME": user})

    cmd_list = [sys.executable, script] + list(args)
    work_dir = cwd or os.path.dirname(os.path.abspath(script))
    log_fh = None

    try:
        if log_file:
            log_dir = os.path.dirname(log_file)
            if log_dir:
                os.makedirs(log_dir, exist_ok=True)
            log_fh = open(log_file, "a", encoding="utf-8")
            proc = subprocess.Popen(
                cmd_list, stdout=log_fh, stderr=subprocess.STDOUT,
                cwd=work_dir, env=env, preexec_fn=_demote,
            )
            proc.communicate(timeout=timeout)
            return proc.returncode, "", ""
        else:
            proc = subprocess.Popen(
                cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=work_dir, env=env, preexec_fn=_demote,
            )
            stdout_b, stderr_b = proc.communicate(timeout=timeout)
            return (
                proc.returncode,
                stdout_b.decode("utf-8", errors="replace").strip(),
                stderr_b.decode("utf-8", errors="replace").strip(),
            )
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        return -1, "", f"Timeout after {timeout}s"
    finally:
        if log_fh:
            log_fh.close()



def _parse_backup_list_line(line):
    """Parse one line of backup file list. Returns (record_size, file_path) or (None, None) if invalid."""
    line = line.strip()
    if not line:
        return None, None
    cleaned = line.replace(" ", "").lstrip("[")
    parts = cleaned.split("]", 1)
    if len(parts) < 2:
        return None, None
    record_size = parts[0]
    file_path = parts[1]
    if not file_path:
        return None, None
    if "->" in file_path:
        file_path = file_path.split("->")[0]
    return record_size, file_path


def check_backup_files(backup_list_file, dest_dir, orig_dir):
    """Verify backup file integrity. Raises FileCheckError on failure."""
    LOGGER.info(f"check backup files in {dest_dir} from {orig_dir}")
    _do_file_check(backup_list_file, dest_dir, orig_dir, mode="backup")


def check_rollback_files(backup_list_file, dest_dir, orig_dir):
    """Verify rollback file integrity. Raises FileCheckError on failure."""
    LOGGER.info(f"check rollback files in {dest_dir} from {orig_dir}")
    _do_file_check(backup_list_file, dest_dir, orig_dir, mode="rollback")


class FileCheckError(Exception):
    """File verification failed."""
    pass


def _do_file_check(backup_list_file, dest_dir, orig_dir, mode="backup"):
    """Unified file check: mode 'backup' checks dest exists, 'rollback' checks orig exists."""
    with open(backup_list_file, "r") as f:
        for line in f:
            record_size, orig_path = _parse_backup_list_line(line)
            if not orig_path:
                continue
            if not orig_path.startswith(orig_dir):
                continue
            if orig_path.startswith(os.path.join(orig_dir, "log")):
                continue

            relative_path = orig_path[len(orig_dir):]
            dest_path = dest_dir + relative_path

            if mode == "backup":
                check_path = dest_path
            else:
                check_path = orig_path

            if not os.path.exists(check_path):
                msg = f"File not found: {orig_path} -> {dest_path}"
                LOGGER.error(msg)
                raise FileCheckError(msg)

            if os.path.isfile(check_path):
                orig_size = os.path.getsize(orig_path) if os.path.exists(orig_path) else 0
                dest_size = os.path.getsize(dest_path) if os.path.exists(dest_path) else 0
                if orig_size != dest_size:
                    msg = (f"File size mismatch: {orig_path}({orig_size}) "
                           f"-> {dest_path}({dest_size})")
                    LOGGER.error(msg)
                    raise FileCheckError(msg)
                if record_size and str(dest_size) != str(record_size):
                    msg = (f"File size differs from record: "
                           f"recorded={record_size}, actual={dest_size}")
                    LOGGER.error(msg)
                    raise FileCheckError(msg)



class CGroupManager:
    """CGroup memory isolation management."""

    def __init__(self, cgroup_path, mem_size_gb=10):
        self.cgroup_path = cgroup_path
        self.mem_size_gb = mem_size_gb

    def create(self):
        """Create cgroup path."""
        os.makedirs(self.cgroup_path, exist_ok=True)
        LOGGER.info(f"cgroup path created: {self.cgroup_path}")

    def configure(self, process_keyword="cms server -start"):
        """Set memory limit and add process."""
        limit_file = os.path.join(self.cgroup_path, "memory.limit_in_bytes")
        tasks_file = os.path.join(self.cgroup_path, "tasks")

        with open(limit_file, "w") as f:
            f.write(f"{self.mem_size_gb}G")
        LOGGER.info(f"cgroup memory limit set to {self.mem_size_gb}G")

        ret, stdout, _ = exec_popen(
            f"ps -ef | grep '{process_keyword}' | grep -v grep | awk 'NR==1 {{print $2}}'"
        )
        if ret == 0 and stdout.strip():
            pid = stdout.strip()
            with open(tasks_file, "w") as f:
                f.write(pid)
            LOGGER.info(f"added pid {pid} to cgroup")

    def clean(self):
        """Clean cgroup."""
        if os.path.isdir(self.cgroup_path):
            try:
                os.rmdir(self.cgroup_path)
                LOGGER.info(f"cgroup removed: {self.cgroup_path}")
            except OSError as e:
                LOGGER.warning(f"failed to remove cgroup: {e}")
        else:
            LOGGER.info("cgroup path does not exist, skip cleaning")

    def setup(self, process_keyword="cms server -start"):
        """Full cgroup setup: clean -> create -> configure"""
        try:
            self.clean()
        except Exception:
            pass
        self.create()



class IPTablesManager:
    """IPTables rule management."""

    @staticmethod
    def _get_iptables_path():
        ret, stdout, _ = exec_popen("whereis iptables")
        if ret == 0 and stdout:
            path = stdout.split(":")[1].strip() if ":" in stdout else ""
            return path
        return ""

    @staticmethod
    def _rule_exists(chain, port):
        """Check if rule exists."""
        ret, stdout, _ = exec_popen(
            f"iptables -L {chain} -w 60 | grep ACCEPT | grep {port} | grep tcp | wc -l"
        )
        return ret == 0 and stdout.strip() != "0"

    @classmethod
    def accept(cls, cms_config_file):
        """Add iptables ACCEPT rules for CMS port."""
        port = cls._read_port(cms_config_file)
        if not port:
            LOGGER.warning("cannot read CMS port, skip iptables")
            return

        if not cls._get_iptables_path():
            LOGGER.info("iptables not found, skip")
            return

        LOGGER.info(f"adding iptables ACCEPT rules for port {port}")
        for chain in ("INPUT", "FORWARD", "OUTPUT"):
            if not cls._rule_exists(chain, port):
                exec_popen(f"iptables -I {chain} -p tcp --sport {port} -j ACCEPT -w 60")

    @classmethod
    def delete(cls, cms_config_file):
        """Remove iptables ACCEPT rules for CMS port."""
        port = cls._read_port(cms_config_file)
        if not port:
            return

        if not cls._get_iptables_path():
            return

        LOGGER.info(f"deleting iptables rules for port {port}")
        for chain in ("INPUT", "FORWARD", "OUTPUT"):
            if cls._rule_exists(chain, port):
                exec_popen(f"iptables -D {chain} -p tcp --sport {port} -j ACCEPT -w 60")

    @staticmethod
    def _read_port(config_file):
        """Read port from cms.ini."""
        if not os.path.exists(config_file):
            return ""
        try:
            with open(config_file, "r") as f:
                for line in f:
                    if "_PORT" in line:
                        return line.split("=")[-1].strip()
        except OSError:
            pass
        return ""



class ProcessManager:
    """Process management utility."""

    CHECK_MAX_TIMES = 7
    CHECK_INTERVAL = 5

    @staticmethod
    def get_pid(process_name):
        """Get process PID."""
        cmd = (
            f"ps -u $(id -un) -o pid=,args= | grep '{process_name}' | "
            "grep -v grep | awk '{print $1}'"
        )
        ret, stdout, stderr = exec_popen(cmd)
        if ret:
            LOGGER.error(f"Failed to get pid for '{process_name}': {stderr}")
            return ""
        return stdout.strip()

    @staticmethod
    def kill_process(process_name):
        """Kill specified process."""
        kill_cmd = (
            f"proc_pid_list=$(ps -u $(id -un) -o pid=,args= | grep '{process_name}' | "
            "grep -v grep | awk '{print $1}') && "
            f'(if [ -n "$proc_pid_list" ]; then echo $proc_pid_list | xargs kill -9; fi)'
        )
        LOGGER.info(f"kill process: {process_name}")
        run_cmd(kill_cmd, f"failed to kill {process_name}")

    @classmethod
    def ensure_stopped(cls, process_name, force_uninstall=None):
        """Ensure process stopped, wait up to CHECK_MAX_TIMES * CHECK_INTERVAL seconds."""
        for i in range(cls.CHECK_MAX_TIMES):
            pid = cls.get_pid(process_name)
            if not pid:
                return
            LOGGER.info(f"check {i+1}/{cls.CHECK_MAX_TIMES}: {process_name} pid={pid}")
            if i < cls.CHECK_MAX_TIMES - 1:
                time.sleep(cls.CHECK_INTERVAL)

        msg = f"Failed to stop {process_name} after {cls.CHECK_MAX_TIMES * cls.CHECK_INTERVAL}s"
        LOGGER.error(msg)
        if force_uninstall != "force":
            raise RuntimeError(msg)

    @staticmethod
    def is_running(process_name):
        """Check if process is running."""
        return bool(ProcessManager.get_pid(process_name))

    @staticmethod
    def clear_shm(shm_home="/dev/shm", shm_pattern="ograc.[0-9]*"):
        """Clear shared memory when ogracd not running. Args: shm_home, shm_pattern."""
        shm_dir_name = os.path.basename(os.path.normpath(shm_home))
        cmd = ("ps -eo args= | grep '[o]gracd' "
               f"| grep '/dev/shm/{shm_dir_name}/'")
        ret, stdout, _ = exec_popen(cmd)
        if ret == 0 and stdout.strip():
            LOGGER.info("ogracd is running, skip shm cleanup")
            return
        if not os.path.isdir(shm_home):
            LOGGER.info(f"shm directory not found: {shm_home}, skip")
            return
        pattern = os.path.join(shm_home, shm_pattern)
        count = 0
        for f in glob_mod.glob(pattern):
            try:
                os.remove(f)
                count += 1
            except OSError:
                pass
        LOGGER.info(f"shared memory cleaned: {count} files from {shm_home}")

    @staticmethod
    def ensure_shm_dir(shm_home, user_and_group=""):
        """Ensure user shm subdir exists with correct permissions (0700). Args: shm_home, user_and_group."""
        if not os.path.isdir(shm_home):
            os.makedirs(shm_home, mode=0o700, exist_ok=True)
            LOGGER.info(f"created shm directory: {shm_home} (mode=0700)")
        if user_and_group:
            exec_popen(f"chown {user_and_group} {shm_home}")
            exec_popen(f"chmod 700 {shm_home}")



def ensure_dir(path, mode=0o750, owner=None):
    """Ensure directory exists and set permissions."""
    os.makedirs(path, mode=mode, exist_ok=True)
    if owner:
        run_cmd(f"chown {owner} -hR {path}", f"failed to chown {path}")


def ensure_file(path, mode=0o640, owner=None):
    """Ensure file exists and set permissions."""
    if not os.path.exists(path):
        with open(path, "w"):
            pass
    os.chmod(path, mode)
    if owner:
        run_cmd(f"chown {owner} {path}", f"failed to chown {path}")


def safe_remove(path):
    """Safely remove file or directory."""
    if os.path.isfile(path) or os.path.islink(path):
        os.remove(path)
    elif os.path.isdir(path):
        import shutil
        shutil.rmtree(path)


def copy_tree(src, dest, owner=None):
    """Copy directory tree."""
    run_cmd(f"cp -arf {src} {dest}", f"failed to copy {src} to {dest}")
    if owner:
        run_cmd(f"chown -hR {owner} {dest}", f"failed to chown {dest}")



def read_version(versions_yml_path):
    """Read version from versions.yml."""
    if not os.path.exists(versions_yml_path):
        return ""
    with open(versions_yml_path, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("Version:"):
                return line.split(":")[1].strip()
    return ""


def get_version_major(versions_yml_path):
    """Get major version (first digit)."""
    version = read_version(versions_yml_path)
    if version:
        return int(version.split(".")[0])
    return 0
