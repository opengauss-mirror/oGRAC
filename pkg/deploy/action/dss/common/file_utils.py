#!/usr/bin/env python3
"""DSS file utilities: VG read/write, 512-byte alignment, hex decode."""

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
    Pad file to 512-byte alignment.
    Args: input_file, output_file (default overwrites input).
    Returns: total bytes after padding.
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
    """Parse string to integer."""
    try:
        return int(float(val))
    except ValueError as e:
        raise ValueError(f"Cannot convert '{val}' to integer.") from e


def get_written_size(vg_file_path):
    """Get actual written size of VG file."""
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
    """Parse hex output from dsscmd examine."""
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
    """Read specified size from VG file."""
    _, stdout, stderr = dsscmd(
        f"examine -p {vg_file_path} -o 0 -f x -s {size}",
        error_msg=f"dsscmd examine {vg_file_path} failed",
    )
    return parse_hex_dump(stdout)


def read_dss_file(vg_file_path):
    """Read full content of VG file."""
    written_size = get_written_size(vg_file_path)
    if written_size == 0:
        return "[Empty] No actual data written to this DSS file."
    return read_dss_content(vg_file_path, written_size)
