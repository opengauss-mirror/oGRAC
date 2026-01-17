# -*- coding: UTF-8 -*-
import sys
import os
import json
from pathlib import Path

INSTALL_SCPRIT_DIR = os.path.dirname(os.path.abspath(__file__))
PKG_DIR = os.path.abspath(os.path.join(INSTALL_SCPRIT_DIR, "../.."))

CONFIG_PARAMS_FILE = os.path.join(PKG_DIR, "config", "deploy_param.json")
OGRAC_CONFIG_PARAMS_FILE = os.path.join(PKG_DIR, "action", "ograc", "ograc_config.json")
OGRAC_CONFIG_PARAMS_FILE_BACKUP = "/opt/ograc/backup/files/ograc/ograc_config.json"
NUMA_CONFIG_FILE = "/opt/ograc/ograc/cfg/cpu_config.json"
OGRAC_START_STATUS_FILE = os.path.join("/opt/ograc/ograc", "cfg", "start_status.json")
OGRAC_START_CONFIG_FILE = os.path.join(PKG_DIR, "config", "container_conf", "init_conf", "start_config.json")
OGRAC_MEM_SPEC_FILE = os.path.join(PKG_DIR, "config", "container_conf", "init_conf", "mem_spec")
ENV_FILE = os.path.join(PKG_DIR, "action", "env.sh")
info = {}
kernel_params_list = ['CPU_GROUP_INFO', 'LARGE_POOL_SIZE', 'CR_POOL_COUNT', 'CR_POOL_SIZE',
                      'TEMP_POOL_NUM', 'BUF_POOL_NUM', 'LOG_BUFFER_SIZE', 'LOG_BUFFER_COUNT',
                      'SHARED_POOL_SIZE', 'DATA_BUFFER_SIZE', 'TEMP_BUFFER_SIZE', 'SESSIONS',
                      "VARIANT_MEMORY_AREA_SIZE", "DTC_RCY_PARAL_BUF_LIST_SIZE"]
numa_params_list = ["OGRAC_NUMA_CPU_INFO", "KERNEL_NUMA_CPU_INFO"]
MEM_SPEC = {
    "0": {
        "SESSIONS": "512",
        "TEMP_BUFFER_SIZE": "1G",
        "LARGE_POOL_SIZE": "256M",
        "DATA_BUFFER_SIZE": "8G",
        "SHARED_POOL_SIZE": "512M",
        "DTC_RCY_PARAL_BUF_LIST_SIZE": "8",
        "VARIANT_MEMORY_AREA_SIZE": "256M",
        "CR_POOL_SIZE": "256M",
        "max_connections": "128",
        "table_open_cache": "5120",
        "table_open_cache_instances": "4"
    },
    "1": {
        "SESSIONS": "1024",
        "TEMP_BUFFER_SIZE": "2G",
        "LARGE_POOL_SIZE": "256M",
        "DATA_BUFFER_SIZE": "30G",
        "SHARED_POOL_SIZE": "512M",
        "DTC_RCY_PARAL_BUF_LIST_SIZE": "8",
        "VARIANT_MEMORY_AREA_SIZE": "256M",
        "CR_POOL_SIZE": "512M",
        "max_connections": "1024",
        "table_open_cache": "10240",
        "table_open_cache_instances": "8"
    },
    "2": {
        "SESSIONS": "2048",
        "TEMP_BUFFER_SIZE": "4G",
        "LARGE_POOL_SIZE": "512M",
        "DATA_BUFFER_SIZE": "60G",
        "SHARED_POOL_SIZE": "1G",
        "DTC_RCY_PARAL_BUF_LIST_SIZE": "16",
        "VARIANT_MEMORY_AREA_SIZE": "512M",
        "CR_POOL_SIZE": "1G",
        "max_connections": "2048",
        "table_open_cache": "20480",
        "table_open_cache_instances": "16"
    },
    "3": {
        "SESSIONS": "4096",
        "TEMP_BUFFER_SIZE": "8G",
        "LARGE_POOL_SIZE": "1G",
        "DATA_BUFFER_SIZE": "120G",
        "SHARED_POOL_SIZE": "2G",
        "DTC_RCY_PARAL_BUF_LIST_SIZE": "32",
        "VARIANT_MEMORY_AREA_SIZE": "1G",
        "CR_POOL_SIZE": "2G",
        "max_connections": "4096",
        "table_open_cache": "40960",
        "table_open_cache_instances": "32"
    }
}


with open(CONFIG_PARAMS_FILE, encoding="utf-8") as f:
    _tmp = f.read()
    info = json.loads(_tmp)

if os.path.exists(OGRAC_CONFIG_PARAMS_FILE_BACKUP):
    with open(OGRAC_CONFIG_PARAMS_FILE_BACKUP, encoding="utf-8") as f:
        _tmp_ograc = f.read()
        info_ograc = json.loads(_tmp_ograc)

if os.path.exists(OGRAC_START_STATUS_FILE):
    with open(OGRAC_START_STATUS_FILE, encoding="utf-8") as f:
        _tmp_ograc = f.read()
        info_ograc_start = json.loads(_tmp_ograc)

if os.path.exists(OGRAC_START_CONFIG_FILE):
    with open(OGRAC_START_CONFIG_FILE, encoding="utf-8") as f:
        _tmp_ograc = f.read()
        info_ograc_config = json.loads(_tmp_ograc)

if os.path.exists(OGRAC_MEM_SPEC_FILE):
    with open(OGRAC_MEM_SPEC_FILE, encoding="utf-8") as f:
        mem_spec = f.read()
    info_ograc_config = MEM_SPEC.get(mem_spec, "1")

if os.path.exists(NUMA_CONFIG_FILE):
    with open(NUMA_CONFIG_FILE, "r", encoding="utf-8") as f:
        numa_config = json.loads(f.read())

with open(ENV_FILE, "r", encoding="utf-8") as f:
    env_config = f.readlines()


def get_value(param):
    if param == 'auto_tune':
        return info.get('auto_tune', '0')
    if param == 'ograc_in_container':
        return info.get('ograc_in_container', '0')
    if param == 'SYS_PASSWORD':
        return info_ograc.get('SYS_PASSWORD', "")
    if param == "deploy_user":
        for line in env_config:
            if line.startswith("ograc_user"):
                return line.split("=")[1].strip("\n").strip('"')
    if param == "deploy_group":
        for line in env_config:
            if line.startswith("ograc_group"):
                return line.split("=")[1].strip("\n").strip('"')
    if param == 'OGRAC_START_STATUS':
        return info_ograc_start.get('start_status', "")
    if param == 'OGRAC_DB_CREATE_STATUS':
        return info_ograc_start.get('db_create_status', "")
    if param == 'OGRAC_EVER_START':
        return info_ograc_start.get('ever_started', "")
    if param in numa_params_list:
        return numa_config.get(param, "")
    if param in kernel_params_list:
        return info_ograc_config.get(param, "")

    return info.get(param, "")


if __name__ == "__main__":
    _param = sys.argv[1]
    res = get_value(_param)
    print(res)

