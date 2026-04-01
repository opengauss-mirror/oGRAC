#!/usr/bin/env python3
"""DSS command wrapper."""

import os
import subprocess
import sys

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CUR_DIR)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

from log_config import get_logger

LOG = get_logger()

_DEFAULT_TIMEOUT = 60



def exec_popen(cmd, timeout=_DEFAULT_TIMEOUT):
    """Execute a shell command."""
    proc = subprocess.Popen(
        ["bash", "-c", cmd],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        stdout_b, stderr_b = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        return -1, "", f"Timeout after {timeout}s"
    return (
        proc.returncode,
        stdout_b.decode(errors="replace").strip(),
        stderr_b.decode(errors="replace").strip(),
    )


def dsscmd(subcmd, error_msg=None, timeout=_DEFAULT_TIMEOUT):
    """
    Execute dsscmd subcommand.

    Args:
        subcmd: Subcommand (without dsscmd prefix), e.g. "ls -p +vg1/upgrade"
        error_msg: Error description on failure; None to suppress exception
        timeout: Timeout in seconds

    Returns:
        (return_code, stdout, stderr)

    Raises:
        RuntimeError: If error_msg is not None and command fails
    """
    cmd = f"dsscmd {subcmd}"
    code, stdout, stderr = exec_popen(cmd, timeout)
    if code != 0 and error_msg:
        raise RuntimeError(f"{error_msg}: {stderr}")
    return code, stdout, stderr



def vg_ls(vg_path, timeout=_DEFAULT_TIMEOUT):
    """List VG directory contents, return (code, stdout, stderr)."""
    return dsscmd(f"ls -p {vg_path}", timeout=timeout)


def vg_file_exists(vg_path):
    """Check if VG file/directory exists."""
    code, _, _ = vg_ls(vg_path)
    return code == 0


def vg_list_files(vg_path):
    """List filenames in VG directory."""
    code, stdout, _ = vg_ls(vg_path)
    if code != 0:
        return None
    lines = stdout.strip().splitlines()
    if len(lines) < 2:
        return []
    return lines


def vg_mkdir(parent_path, dir_name):
    """Create directory in VG."""
    dsscmd(f"mkdir -p {parent_path} -d {dir_name}",
           error_msg=f"dsscmd mkdir {parent_path}/{dir_name} failed")


def vg_touch(vg_path):
    """Create empty file in VG."""
    dsscmd(f"touch -p {vg_path}",
           error_msg=f"dsscmd touch {vg_path} failed")


def vg_rm(vg_path):
    """Remove VG file."""
    dsscmd(f"rm -p {vg_path}",
           error_msg=f"dsscmd rm {vg_path} failed")


def vg_rmdir(vg_path, recursive=True):
    """Remove VG directory."""
    r_flag = " -r" if recursive else ""
    dsscmd(f"rmdir -p {vg_path}{r_flag}",
           error_msg=f"dsscmd rmdir {vg_path} failed")


def vg_cp(src, dst):
    """Copy file in VG."""
    dsscmd(f"cp -s {src} -d {dst}",
           error_msg=f"dsscmd cp {src} → {dst} failed")


def vg_find_matching_files(vg_path, keyword):
    """
    Find files containing keyword in VG directory, return filename list.
    dsscmd ls output format: written_size block_size flag ... name
    """
    lines = vg_list_files(vg_path)
    if lines is None or len(lines) == 0:
        return []
    result = []
    for line in lines:
        if "written_size" in line:
            continue
        if keyword in line:
            parts = line.strip().split()
            if len(parts) >= 6:
                result.append(parts[5])
            elif parts:
                result.append(parts[-1])
    return result
