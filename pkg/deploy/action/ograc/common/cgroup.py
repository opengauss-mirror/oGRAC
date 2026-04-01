#!/usr/bin/env python3
"""oGRAC cgroup management."""

import os
import re

from config import cfg
from log_config import get_logger
from utils import exec_popen

LOG = get_logger()


def ensure_cgroup_dir():
    path = cfg.paths.instance.cgroup_memory_path
    if os.path.isdir(path):
        try:
            os.rmdir(path)
        except OSError:
            pass
    os.makedirs(path, exist_ok=True)
    LOG.info(f"cgroup dir ensured: {path}")
    return path


def remove_cgroup_dir():
    path = cfg.paths.instance.cgroup_memory_path
    if os.path.isdir(path):
        try:
            os.rmdir(path)
        except OSError as e:
            LOG.warning(f"remove cgroup dir failed (maybe not empty): {e}")
    LOG.info("ogracd cgroup config is removed.")


def _resolve_uid(user: str) -> str:
    """Convert username to UID string; return as-is if already numeric or lookup fails."""
    if user.isdigit():
        return user
    try:
        import pwd as _pwd
        return str(_pwd.getpwnam(user).pw_uid)
    except (KeyError, ImportError):
        return ""


def list_ogracd_pids(data_path: str, user: str = ""):
    """Find ogracd PIDs matching the given data directory."""
    escaped = re.escape(data_path)
    cmd = "ps -eo pid=,uid=,args= | grep '[o]gracd'"
    if user:
        uid = _resolve_uid(user)
        if uid:
            cmd += f" | awk '$2=={uid} {{print}}'"
    cmd += f" | grep -E -- '-D[[:space:]]+{escaped}([[:space:]]|$)' | awk '{{print $1}}'"
    rc, out, err = exec_popen(cmd, timeout=30)
    if rc not in (0, 1):
        LOG.error("Failed to list ogracd pid for %s: %s", data_path, err)
        return []
    return [line.strip() for line in out.splitlines() if line.strip()]


def attach_ogracd_pid(pid):
    """Write ogracd PIDs into cgroup tasks file."""
    path = cfg.paths.instance.cgroup_memory_path
    tasks = os.path.join(path, "tasks")
    pid_list = pid if isinstance(pid, (list, tuple)) else str(pid).split()
    success = True
    for single_pid in pid_list:
        cmd = f"sh -c \"echo {single_pid} > {tasks}\""
        rc, out, err = exec_popen(cmd, timeout=30)
        if rc == 0:
            LOG.info(f"ogracd pid : {single_pid} success")
            continue
        LOG.error(f"ogracd pid : {single_pid} failed: {out}{err}")
        success = False
    return success


def set_memory_limit_mb(limit_mb: int):
    """Set memory.limit_in_bytes (cgroup v1)."""
    if limit_mb <= 0:
        return
    path = cfg.paths.instance.cgroup_memory_path
    limit_file = os.path.join(path, "memory.limit_in_bytes")
    bytes_val = int(limit_mb) * 1024 * 1024
    with open(limit_file, "w", encoding="utf-8") as f:
        f.write(str(bytes_val))
    LOG.info(f"Set cgroup memory limit: {limit_mb}MB ({bytes_val} bytes)")

