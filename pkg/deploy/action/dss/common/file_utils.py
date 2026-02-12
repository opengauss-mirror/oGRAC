"""
DSS 文件工具模块

提供 VG 文件的读写、512 字节对齐、十六进制解码等功能。
"""

import os
import re
import sys

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CUR_DIR)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

from common.dss_cmd import dsscmd


def pad_file_to_512(input_file, output_file=None):
    """
    将文件填充到 512 字节对齐。

    Args:
        input_file: 源文件路径
        output_file: 目标文件路径（默认覆盖源文件）

    Returns:
        填充后的总字节数
    """
    if not os.path.isfile(input_file):
        raise FileNotFoundError(f"Input file '{input_file}' not found.")

    with open(input_file, 'rb') as f:
        data = f.read()

    original_size = len(data)
    pad_size = (512 - original_size % 512) % 512
    if pad_size:
        data += b'\x00' * pad_size

    target = output_file or input_file
    with open(target, 'wb') as f:
        f.write(data)

    return len(data)


def parse_numeric(val):
    """将字符串解析为整数"""
    try:
        return int(float(val))
    except ValueError as e:
        raise ValueError(f"Cannot convert '{val}' to integer.") from e


def get_written_size(vg_file_path):
    """获取 VG 文件的实际写入大小"""
    code, stdout, stderr = dsscmd(f"ls -p {vg_file_path} -w 0")
    no_file_result = f"The path {vg_file_path} is not exsit."

    if stdout.strip() == no_file_result:
        return 0
    if code != 0:
        raise RuntimeError(f"`dsscmd ls` failed: {stderr}")

    lines = stdout.strip().splitlines()
    if len(lines) < 2:
        raise ValueError("Unexpected `dsscmd ls` output: too few lines.")

    headers = lines[0].split()
    values = lines[1].split()

    if 'written_size' not in headers:
        raise ValueError("'written_size' column not found.")

    idx = headers.index('written_size')
    return parse_numeric(values[idx])


def parse_hex_dump(raw_output):
    """解析 dsscmd examine 的十六进制输出"""
    hex_bytes = []
    for line in raw_output.strip().splitlines():
        matches = re.findall(r'\b[0-9a-fA-F]{2}\b', line)
        if matches:
            hex_bytes.extend(matches)

    try:
        byte_data = bytes.fromhex(''.join(hex_bytes))
        return byte_data.replace(b'\x00', b'').decode('utf-8', errors='replace').strip()
    except Exception as e:
        raise ValueError(f"Failed to decode hex dump: {e}") from e


def read_dss_content(vg_file_path, size):
    """从 VG 文件读取指定大小的内容"""
    _, stdout, stderr = dsscmd(
        f"examine -p {vg_file_path} -o 0 -f x -s {size}",
        error_msg=f"dsscmd examine {vg_file_path} failed",
    )
    return parse_hex_dump(stdout)


def read_dss_file(vg_file_path):
    """读取 VG 文件的全部内容"""
    written_size = get_written_size(vg_file_path)
    if written_size == 0:
        return "[Empty] No actual data written to this DSS file."
    return read_dss_content(vg_file_path, written_size)
