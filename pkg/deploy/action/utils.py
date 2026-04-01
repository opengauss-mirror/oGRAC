#!/usr/bin/env python3
"""oGRAC shared utilities."""

import grp
import os
import pwd
import re
import shutil
import signal
import subprocess
import stat
import json
from pathlib import Path
from log_config import get_logger

LOG = get_logger("deploy")


class CommandError(Exception):
    pass


def exec_popen(cmd, timeout=1800):
    """Execute shell command, return (returncode, stdout, stderr)."""
    proc = subprocess.Popen(
        ["bash", "-c", cmd],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        return -1, "", "timeout"
    return proc.returncode, stdout.decode().strip(), stderr.decode().strip()


def run_cmd(cmd, error_msg="command failed", timeout=1800):
    """Execute command, raise CommandError on failure."""
    ret, stdout, stderr = exec_popen(cmd, timeout=timeout)
    if ret != 0:
        raise CommandError(f"{error_msg}: ret={ret}, stderr={stderr}")
    return stdout


def run_as_user(cmd, user, timeout=1800):
    """Execute shell command as specified user."""
    full_cmd = f'su -s /bin/bash - {user} -c "{cmd}"'
    return exec_popen(full_cmd, timeout=timeout)


def run_python_as_user(script, args, user, timeout=1800):
    """
    Execute Python script as specified user.
    Uses preexec_fn + setuid, no shell injection risk.
    """
    try:
        pw = pwd.getpwnam(user)
    except KeyError:
        raise CommandError(f"User {user} not found")

    def _set_user():
        os.setgid(pw.pw_gid)
        os.initgroups(user, pw.pw_gid)
        os.setuid(pw.pw_uid)

    cmd_list = ["python3", script] + list(args)
    proc = subprocess.Popen(
        cmd_list,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=_set_user,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        return -1, "", "timeout"
    return proc.returncode, stdout.decode().strip(), stderr.decode().strip()


def ensure_dir(path, mode=0o755, user=None, group=None):
    """Ensure directory exists, optionally set permissions and owner."""
    os.makedirs(path, mode=mode, exist_ok=True)
    try:
        os.chmod(path, mode)
    except OSError as e:
        LOG.warning("Failed to chmod %s: %s", path, e)
    if user and group:
        try:
            uid = pwd.getpwnam(user).pw_uid
            gid = grp.getgrnam(group).gr_gid
            os.chown(path, uid, gid)
        except (KeyError, OSError) as e:
            LOG.warning("Failed to chown %s: %s", path, e)


def ensure_file(path, mode=0o640, user=None, group=None):
    """Ensure file exists."""
    if not os.path.exists(path):
        Path(path).touch(mode=mode)
    os.chmod(path, mode)
    if user and group:
        try:
            uid = pwd.getpwnam(user).pw_uid
            gid = grp.getgrnam(group).gr_gid
            os.chown(path, uid, gid)
        except (KeyError, OSError):
            pass


def safe_remove(path):
    """Safely remove file or directory."""
    try:
        if os.path.isdir(path):
            shutil.rmtree(path)
        elif os.path.exists(path):
            os.remove(path)
    except OSError as e:
        LOG.warning("Failed to remove %s: %s", path, e)


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


def copy_tree(src, dst):
    """Copy directory tree."""
    if os.path.isdir(src):
        _copytree_compat(src, dst)
    else:
        shutil.copy2(src, dst)


def read_json(filepath):
    """Read JSON file."""
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json(filepath, data, mode=0o644):
    """Write JSON file."""
    flags = os.O_RDWR | os.O_CREAT | os.O_TRUNC
    modes = stat.S_IRWXU | stat.S_IROTH | stat.S_IRGRP
    with os.fdopen(os.open(filepath, flags, modes), 'w') as f:
        f.write(json.dumps(data, indent=4))


def ini_replace(filepath, key_pattern, new_value):
    """Replace value in INI file using regex."""
    pattern = re.compile(rf'^(\s*{key_pattern}\s*=\s*).*$', re.MULTILINE)
    with open(filepath, 'r') as f:
        content = f.read()
    content = pattern.sub(rf'\g<1>{new_value}', content)
    with open(filepath, 'w') as f:
        f.write(content)


def read_version(versions_file):
    """Read version from versions.yml."""
    if not os.path.exists(versions_file):
        return ""
    with open(versions_file, "r") as f:
        for line in f:
            if "Version:" in line:
                return line.split(":", 1)[1].strip()
    return ""


def chown_recursive(path, user, group):
    """Recursively change file ownership."""
    try:
        uid = pwd.getpwnam(user).pw_uid
        gid = grp.getgrnam(group).gr_gid
    except KeyError:
        LOG.warning("User %s or group %s not found", user, group)
        return
    for root, dirs, files in os.walk(path):
        os.chown(root, uid, gid)
        for d in dirs:
            os.chown(os.path.join(root, d), uid, gid)
        for f in files:
            try:
                os.lchown(os.path.join(root, f), uid, gid)
            except OSError:
                pass


def is_process_running(name_pattern):
    """Check if process matching name is running."""
    ret, stdout, _ = exec_popen(
        f"ps -ef | grep '{name_pattern}' | grep -v grep | awk '{{print $2}}'")
    return bool(stdout.strip()) if ret == 0 else False


def kill_process(name_pattern):
    """Kill process matching name."""
    ret, stdout, _ = exec_popen(
        f"ps -ef | grep '{name_pattern}' | grep -v grep | awk '{{print $2}}'")
    if ret == 0 and stdout.strip():
        for pid in stdout.strip().split("\n"):
            try:
                os.kill(int(pid.strip()), signal.SIGKILL)
            except (ProcessLookupError, ValueError):
                pass
