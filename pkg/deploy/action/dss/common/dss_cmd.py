"""
DSS 命令统一封装

替代原来各升级模块中分散的 dsscmd 调用，消除重复代码。
所有 dsscmd 操作收敛到此模块，业务模块只调用高级 API。
"""

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
    """统一命令执行函数"""
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
    执行 dsscmd 子命令。

    Args:
        subcmd: 子命令 (不含 dsscmd 前缀)，如 "ls -p +vg1/upgrade"
        error_msg: 失败时的错误描述，为 None 时不抛异常
        timeout: 超时秒数

    Returns:
        (return_code, stdout, stderr)

    Raises:
        RuntimeError: 如果 error_msg 不为 None 且命令失败
    """
    cmd = f"dsscmd {subcmd}"
    code, stdout, stderr = exec_popen(cmd, timeout)
    if code != 0 and error_msg:
        raise RuntimeError(f"{error_msg}: {stderr}")
    return code, stdout, stderr



def vg_ls(vg_path, timeout=_DEFAULT_TIMEOUT):
    """列出 VG 目录内容，返回 (code, stdout, stderr)"""
    return dsscmd(f"ls -p {vg_path}", timeout=timeout)


def vg_file_exists(vg_path):
    """检查 VG 文件/目录是否存在"""
    code, _, _ = vg_ls(vg_path)
    return code == 0


def vg_list_files(vg_path):
    """列出 VG 目录中的文件名列表"""
    code, stdout, _ = vg_ls(vg_path)
    if code != 0:
        return None
    lines = stdout.strip().splitlines()
    if len(lines) < 2:
        return []
    return lines


def vg_mkdir(parent_path, dir_name):
    """在 VG 中创建目录"""
    dsscmd(f"mkdir -p {parent_path} -d {dir_name}",
           error_msg=f"dsscmd mkdir {parent_path}/{dir_name} failed")


def vg_touch(vg_path):
    """在 VG 中创建空文件"""
    dsscmd(f"touch -p {vg_path}",
           error_msg=f"dsscmd touch {vg_path} failed")


def vg_rm(vg_path):
    """删除 VG 文件"""
    dsscmd(f"rm -p {vg_path}",
           error_msg=f"dsscmd rm {vg_path} failed")


def vg_rmdir(vg_path, recursive=True):
    """删除 VG 目录"""
    r_flag = " -r" if recursive else ""
    dsscmd(f"rmdir -p {vg_path}{r_flag}",
           error_msg=f"dsscmd rmdir {vg_path} failed")


def vg_cp(src, dst):
    """在 VG 中拷贝文件"""
    dsscmd(f"cp -s {src} -d {dst}",
           error_msg=f"dsscmd cp {src} → {dst} failed")


def vg_find_matching_files(vg_path, keyword):
    """
    在 VG 目录中查找包含 keyword 的文件，返回文件名列表。

    dsscmd ls 输出格式示例：
        written_size   block_size   flag   ...   name
        512            1024         0      ...   upgrade_lock_0
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
