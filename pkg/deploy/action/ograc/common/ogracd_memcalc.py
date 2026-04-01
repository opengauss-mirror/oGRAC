#!/usr/bin/env python3
"""
ogracd cgroup memory limit calculation (Python port).

Reads parameters from ogracd.ini and estimates reserved memory (MB)
using the formula from the original ogracd_cgroup_calculate.sh.
"""
import os
import re

from config import cfg
from log_config import get_logger

LOG = get_logger()

LOG_BUF_AND_MES_POOL_SIZE = 3072
REFORM_MEM_SIZE = 25600
SESSION_SIZE_BYTES = 2566824

NODE_COUNT = 2
PAGE_SIZE = 8192
OTHER_DLS_COUNT = 61024
TABLE_SIZE = 13
DLS_CNT_PER_TABLE = 33795
RES_BUCKET_SIZE = 12
BUF_RES_SIZE = 144
LOCAL_DLS_RES_SIZE = 48
GLOBAL_DLS_RES_SIZE = 120


def _parse_mb(value: str) -> int:
    """Parse memory value like 512M / 1G / 1024 (plain number). Supports M/G/digits."""
    v = value.strip()
    m = re.match(r"^(\d+)([MmGg])?$", v)
    if not m:
        digits = re.sub(r"\D", "", v)
        if not digits:
            return 0
        return int(digits)
    num = int(m.group(1))
    unit = (m.group(2) or "").upper()
    if unit == "G":
        return num * 1024
    return num


def _read_ini_kv(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    kv = {}
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            kv[k.strip()] = v.strip()
    return kv


def calculate_reserved_mem_mb(ini_path=None):
    # type: (str) -> int
    ini_path = ini_path or cfg.paths.ogracd_ini
    if not os.path.exists(ini_path):
        LOG.warning(f"{ini_path} not exist, limited ogracd memory skipped")
        return 0

    kv = _read_ini_kv(ini_path)
    default_mem_mb = LOG_BUF_AND_MES_POOL_SIZE + REFORM_MEM_SIZE

    data_buffer_mb = 0
    shared_pool_mb = 0

    for key in (
        "TEMP_BUFFER_SIZE",
        "DATA_BUFFER_SIZE",
        "SHARED_POOL_SIZE",
        "CR_POOL_SIZE",
        "LARGE_POOL_SIZE",
        "VARIANT_MEMORY_AREA_SIZE",
    ):
        if key in kv:
            mb = _parse_mb(kv[key])
            default_mem_mb += mb
            if key == "DATA_BUFFER_SIZE":
                data_buffer_mb = mb
            if key == "SHARED_POOL_SIZE":
                shared_pool_mb = mb

    for k, v in kv.items():
        if "_INDEX_BUFFER_SIZE" in k:
            default_mem_mb += _parse_mb(v)

    if "SESSIONS" in kv:
        sessions = int(re.sub(r"\D", "", kv["SESSIONS"]) or "0")
        session_mem_mb = sessions * SESSION_SIZE_BYTES // 1024 // 1024
        default_mem_mb += session_mem_mb

    size_mb = 1024 * 1024
    buf_res_cnt = (data_buffer_mb * size_mb // PAGE_SIZE) * NODE_COUNT
    buf_res_mem_mb = (buf_res_cnt * 2 * RES_BUCKET_SIZE + buf_res_cnt * BUF_RES_SIZE) // size_mb

    dc_pool_size = shared_pool_mb // 2
    total_table_dls_cnt = (dc_pool_size // TABLE_SIZE) * DLS_CNT_PER_TABLE
    local_dls_res_cnt = total_table_dls_cnt // 10 + OTHER_DLS_COUNT
    segment_ratio_cnt = (total_table_dls_cnt * 9) // 10
    local_dls_res_cnt += min(buf_res_cnt, segment_ratio_cnt)
    local_dls_mem_mb = (local_dls_res_cnt * 2 * RES_BUCKET_SIZE + local_dls_res_cnt * LOCAL_DLS_RES_SIZE) // size_mb

    global_dls_res_cnt = local_dls_res_cnt * NODE_COUNT
    global_dls_mem_mb = (global_dls_res_cnt * 2 * RES_BUCKET_SIZE + global_dls_res_cnt * GLOBAL_DLS_RES_SIZE) // size_mb

    default_mem_mb += (buf_res_mem_mb + local_dls_mem_mb + global_dls_mem_mb)
    return int(default_mem_mb)

