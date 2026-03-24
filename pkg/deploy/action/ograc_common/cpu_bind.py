#!/usr/bin/env python3
"""CPU binding configuration for the new deployment flow.

Detects NUMA topology, calculates CPU core assignments for database
modules (XNET, MES), and writes cpu_config.json.

Usage:
    python3 cpu_bind.py init_config   # create cpu_bind_config.json template
    python3 cpu_bind.py               # detect NUMA & generate cpu_config.json

Fully decoupled from storage_deploy — uses ograc_common/config.py for
all path resolution.
"""

import configparser
import json
import logging
import logging.handlers
import os
import platform
import pwd
import grp
import re
import stat
import subprocess
import sys

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, CUR_DIR)

from config import cfg as _cfg

# ---------------------------------------------------------------------------
# Logging  (console + optional file)
# ---------------------------------------------------------------------------
LOG = logging.getLogger("cpu_bind")
if not LOG.handlers:
    _sh = logging.StreamHandler(sys.stderr)
    _sh.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s [cpu_bind] %(message)s"))
    LOG.addHandler(_sh)
    LOG.setLevel(logging.INFO)

    _log_dir = os.path.join(_cfg.paths.ograc_home, "log", "ograc")
    try:
        if not os.path.isdir(_log_dir):
            os.makedirs(_log_dir, exist_ok=True)
        _fh = logging.handlers.RotatingFileHandler(
            os.path.join(_log_dir, "cpu_bind.log"),
            maxBytes=6 * 1024 * 1024, backupCount=5)
        _fh.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s [%(funcName)s] %(message)s"))
        LOG.addHandler(_fh)
    except (PermissionError, OSError):
        pass

# ---------------------------------------------------------------------------
# Dynamic paths
# ---------------------------------------------------------------------------
_OGRAC_HOME = _cfg.paths.ograc_home
_OGRAC_DIR = _cfg.paths.ograc_dir
_DATA_ROOT = _cfg.paths.data_root
_DBSTOR_DIR = _cfg.paths.dbstor_dir
_CMS_DIR = _cfg.paths.cms_dir

CPU_CONFIG_FILE = os.path.join(_OGRAC_DIR, "cfg", "cpu_config.json")
CPU_BIND_CONFIG = os.path.join(CUR_DIR, "cpu_bind_config.json")
DATA_DIR = os.path.join(_DATA_ROOT, "local", "ograc", "tmp", "data")

XNET_MODULE = "NETWORK_BIND_CPU"
MES_MODULE = "MES_BIND_CPU"
MES_CPU_INFO = "MES_CPU_INFO"
OGRAC_NUMA_INFO = "OGRAC_NUMA_CPU_INFO"
KERNEL_NUMA_INFO = "KERNEL_NUMA_CPU_INFO"
MODULE_LIST = [XNET_MODULE, MES_MODULE]

DBSTOR_MODULE_MAP = {
    "XNET_CPU": XNET_MODULE,
    "MES_CPU": MES_MODULE,
    "IOD_CPU": "",
    "ULOG_CPU": "",
}

BIND_NUMA_NODE_NUM = 2


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _exec_popen(cmd):
    proc = subprocess.Popen(
        ["bash"], shell=False,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.stdin.write(cmd.encode())
    proc.stdin.write(os.linesep.encode())
    try:
        stdout, stderr = proc.communicate(timeout=60)
    except subprocess.TimeoutExpired:
        proc.kill()
        return -1, "", "timeout"
    out = stdout.decode()
    err = stderr.decode()
    if out.endswith(os.linesep):
        out = out[:-1]
    if err.endswith(os.linesep):
        err = err[:-1]
    return proc.returncode, out, err


def cpu_info_to_cpu_list(cpu_str):
    if not cpu_str:
        return []
    result = []
    for part in cpu_str.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = map(int, part.split("-"))
            result.extend(range(lo, hi + 1))
        else:
            result.append(int(part))
    return result


def cpu_list_to_cpu_info(cpu_list):
    if isinstance(cpu_list, str):
        cpu_list = cpu_list.split(",")
    nums = sorted(set(map(int, cpu_list)))
    if not nums:
        return ""
    ranges, start, end = [], nums[0], nums[0]
    for n in nums[1:]:
        if n == end + 1:
            end = n
        else:
            ranges.append(str(start) if start == end else f"{start}-{end}")
            start = end = n
    ranges.append(str(start) if start == end else f"{start}-{end}")
    return ",".join(ranges)


def _read_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _write_json(path, data):
    cfg_dir = os.path.dirname(path)
    if cfg_dir and not os.path.isdir(cfg_dir):
        os.makedirs(cfg_dir, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT
    mode = stat.S_IWUSR | stat.S_IRUSR
    with os.fdopen(os.open(path, flags, mode), "w") as f:
        f.truncate()
        json.dump(data, f, indent=4)
    os.chmod(path, stat.S_IWUSR | stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    try:
        uid = pwd.getpwnam(_cfg.user).pw_uid
        gid = grp.getgrnam(_cfg.group).gr_gid
        os.chown(path, uid, gid)
    except (KeyError, PermissionError, OSError) as e:
        LOG.warning("chown %s failed: %s", path, e)


# ---------------------------------------------------------------------------
# dbstor.ini helper  (replaces storage_deploy/update_config.py)
# ---------------------------------------------------------------------------

def _dbstor_ini_files():
    data_dbs = os.path.join(DATA_DIR, "dbstor", "conf", "dbs")
    ograc_dbs = os.path.join(_DBSTOR_DIR, "conf", "dbs")
    ograc_tools = os.path.join(_DBSTOR_DIR, "tools")
    cms_dbs = os.path.join(_CMS_DIR, "dbstor", "conf", "dbs")
    return [
        os.path.join(data_dbs, "dbstor_config.ini"),
        os.path.join(ograc_dbs, "dbstor_config.ini"),
        os.path.join(ograc_dbs, "dbstor_config_tool_1.ini"),
        os.path.join(ograc_dbs, "dbstor_config_tool_2.ini"),
        os.path.join(ograc_dbs, "dbstor_config_tool_3.ini"),
        os.path.join(ograc_tools, "dbstor_config.ini"),
        os.path.join(cms_dbs, "dbstor_config_tool_1.ini"),
        os.path.join(cms_dbs, "dbstor_config_tool_2.ini"),
        os.path.join(cms_dbs, "dbstor_config_tool_3.ini"),
        os.path.join(cms_dbs, "dbstor_config.ini"),
    ]


def _modify_ini(path, section, key, action, value=None):
    cfg = configparser.ConfigParser()
    cfg.optionxform = str
    cfg.read(path)
    if action == "add":
        if section not in cfg:
            cfg[section] = {}
        cfg[section][key] = value
    else:
        if section in cfg and key in cfg[section]:
            cfg.remove_option(section, key)
    flags = os.O_CREAT | os.O_RDWR
    modes = stat.S_IWUSR | stat.S_IRUSR
    with os.fdopen(os.open(path, flags, modes), "w") as f:
        f.truncate(0)
        cfg.write(f)


def _update_dbstor_conf(action, key, value=None):
    for fp in _dbstor_ini_files():
        if os.path.exists(fp):
            try:
                _modify_ini(fp, "CLIENT", key, action, value)
            except (PermissionError, OSError) as e:
                LOG.warning("Cannot update %s: %s", fp, e)


# ---------------------------------------------------------------------------
# ogracd.ini helper
# ---------------------------------------------------------------------------

def _update_ogracd_ini(ogracd_cpu_info):
    ini_path = os.path.join(DATA_DIR, "cfg", "ogracd.ini")
    if not os.path.exists(ini_path):
        LOG.warning("ogracd.ini not found: %s", ini_path)
        return
    try:
        with open(ini_path, "r+", encoding="utf-8") as f:
            lines = f.readlines()
            existing = {l.split("=", maxsplit=1)[0].strip() for l in lines if "=" in l}

            updated, removed = set(), set()
            new_lines = []
            for line in lines:
                if "=" not in line:
                    new_lines.append(line)
                    continue
                k = line.split("=", maxsplit=1)[0].strip()
                if k in ogracd_cpu_info and ogracd_cpu_info[k] in ("-del", "-remove"):
                    removed.add(k)
                    continue
                if k in ogracd_cpu_info:
                    new_lines.append(f"{k} = {ogracd_cpu_info[k]}\n")
                    updated.add(k)
                else:
                    new_lines.append(line)
            for k, v in ogracd_cpu_info.items():
                if k not in existing and v not in ("-del", "-remove"):
                    new_lines.append(f"{k} = {v}\n")
                    updated.add(k)

            f.seek(0)
            f.writelines(new_lines)
            f.truncate()

        if updated:
            LOG.info("Updated keys in %s: %s", ini_path, ", ".join(updated))
        if removed:
            LOG.info("Removed keys in %s: %s", ini_path, ", ".join(removed))
    except (PermissionError, OSError) as e:
        LOG.warning("Cannot update ogracd.ini: %s", e)


# ---------------------------------------------------------------------------
# Core NUMA classes  (logic extracted from bind_cpu_config.py, paths decoupled)
# ---------------------------------------------------------------------------

class _NumaBase:
    def __init__(self):
        self.all_cpu_list = []
        self.available_cpu_for_binding_dict = {}
        self.bind_cpu_list = []
        self.bind_cpu_dict = {}

    @staticmethod
    def get_default_bind_num(cpu_len):
        if cpu_len <= 16:
            return 1
        elif cpu_len <= 32:
            return 2
        return 4

    def pre_check(self):
        if platform.machine() != "aarch64":
            LOG.info("System is not aarch64")
            return
        if not os.path.exists(CPU_BIND_CONFIG):
            raise RuntimeError(f"cpu_bind_config.json not found: {CPU_BIND_CONFIG}")

    def _update_dbstor(self, cpu_config_info):
        for dbstor_key, mod_key in DBSTOR_MODULE_MAP.items():
            if not mod_key:
                continue
            id_key = f"{mod_key}_ID"
            if id_key in cpu_config_info and cpu_config_info[id_key]:
                _update_dbstor_conf("add", dbstor_key,
                                    cpu_list_to_cpu_info(cpu_config_info[id_key]))
            else:
                _update_dbstor_conf("remove", dbstor_key)

    def get_module_bind_cpu_list(self, thread_num):
        result = []
        pointers = {nid: 0 for nid in self.available_cpu_for_binding_dict}
        count = thread_num
        while count > 0:
            for nid, avail in self.available_cpu_for_binding_dict.items():
                if pointers[nid] < len(avail):
                    result.append(avail[pointers[nid]])
                    pointers[nid] += 1
                    count -= 1
                    if count == 0:
                        break
        for nid, avail in self.available_cpu_for_binding_dict.items():
            self.available_cpu_for_binding_dict[nid] = avail[pointers[nid]:]
        return result


class PhysicalCpuConfig(_NumaBase):

    def __init__(self):
        super().__init__()
        self.numa_info_dict = {}

    def _check_invalid(self, cpus):
        invalid = {0, 1, 2, 3, 4, 5}
        in_container = _cfg.get_deploy_param("ograc_in_container", "0")
        for c in cpus:
            if c in invalid and in_container == "0":
                LOG.error("invalid cpu id: %d", c)
                return True
            if c not in self.all_cpu_list:
                LOG.error("invalid cpu id: %d (not in online list)", c)
                return True
        return False

    def init_cpu_info(self):
        rc, out, err = _exec_popen('/usr/bin/lscpu | grep -i "On-line CPU(s) list"')
        if rc:
            raise RuntimeError(f"Failed to get CPU list: {err}")
        parts = out.strip().split(":")
        if len(parts) != 2:
            raise RuntimeError(f"NUMA info parsing failed: {out}")
        self.all_cpu_list = cpu_info_to_cpu_list(parts[1].strip())

        rc, out, err = _exec_popen('/usr/bin/lscpu | grep -i "NUMA node[0-9] CPU(s)"')
        if rc:
            raise RuntimeError(f"Failed to get NUMA node info: {err}")

        self.numa_info_dict = {}
        for line in out.strip().splitlines():
            m = re.search(r"NUMA node(\d+) CPU\(s\):\s+([\d,\-]+)", line)
            if m:
                self.numa_info_dict[int(m.group(1))] = cpu_info_to_cpu_list(m.group(2))

        self.available_cpu_for_binding_dict = {}
        for nid, cpus in list(self.numa_info_dict.items())[:BIND_NUMA_NODE_NUM]:
            self.available_cpu_for_binding_dict[nid] = [c for c in cpus if c >= 12]

        if not self.available_cpu_for_binding_dict or any(
                not v for v in self.available_cpu_for_binding_dict.values()):
            raise RuntimeError("No valid CPUs available for binding")

    def update_bind_cpu_info(self):
        numa_cfg = _read_json(CPU_BIND_CONFIG)

        for mod in MODULE_LIST:
            mod_info = numa_cfg.get(mod, "")
            id_key = f"{mod}_ID"

            if mod_info == "off":
                numa_cfg[id_key] = ""
                continue

            if id_key in numa_cfg and numa_cfg[id_key]:
                manual = cpu_info_to_cpu_list(numa_cfg[id_key])
                if self._check_invalid(manual):
                    raise RuntimeError(f"Invalid CPU binding in {id_key}")
                LOG.info("%s is manually configured, skipping generation", id_key)
                self.bind_cpu_list.extend(manual)
                continue

            if not mod_info:
                mod_info = self.get_default_bind_num(len(self.all_cpu_list))

            try:
                mod_info = int(mod_info)
                if not 1 <= mod_info <= 10:
                    LOG.warning("Module %s thread number out of range (1-10)", mod)
                    numa_cfg[id_key] = ""
                    continue
            except ValueError:
                LOG.warning("Module %s thread number invalid", mod)
                numa_cfg[id_key] = ""
                continue

            cpus = self.get_module_bind_cpu_list(mod_info)
            self.bind_cpu_list.extend(cpus)
            self.bind_cpu_dict[id_key] = ",".join(map(str, cpus))

    def _get_kernel_cpu_info(self):
        remaining = {nid: list(cl) for nid, cl in self.numa_info_dict.items()}
        for c in self.bind_cpu_list:
            for cl in remaining.values():
                if c in cl:
                    cl.remove(c)
        return " ".join(cpu_list_to_cpu_info(cl) for cl in remaining.values() if cl)

    def finalize(self):
        info = dict(self.bind_cpu_dict)
        remaining = sorted(set(self.all_cpu_list) - set(self.bind_cpu_list))
        info[OGRAC_NUMA_INFO] = cpu_list_to_cpu_info(remaining)
        self._update_dbstor(info)

        kernel = self._get_kernel_cpu_info()
        ogracd = {"CPU_GROUP_INFO": kernel}
        mes_key = f"{MES_MODULE}_ID"
        if info.get(mes_key):
            ogracd[MES_CPU_INFO] = cpu_list_to_cpu_info(info[mes_key])
        else:
            ogracd[MES_CPU_INFO] = "-del"
        _update_ogracd_ini(ogracd)

        info[KERNEL_NUMA_INFO] = kernel
        _write_json(CPU_CONFIG_FILE, info)
        LOG.info("cpu_config.json written to %s", CPU_CONFIG_FILE)

    def run(self):
        self.init_cpu_info()
        self.update_bind_cpu_info()
        self.finalize()


class ContainerCpuConfig(_NumaBase):

    def init_cpu_info(self):
        cpuset = "/sys/fs/cgroup/cpuset/cpuset.cpus"
        if not os.path.exists(cpuset):
            raise RuntimeError("cpuset.cpus not found in container")
        rc, out, err = _exec_popen(f"cat {cpuset}")
        if rc:
            raise RuntimeError(f"Failed to read cpuset: {err}")
        self.all_cpu_list = cpu_info_to_cpu_list(out.strip())
        mid = len(self.all_cpu_list) // 2
        self.available_cpu_for_binding_dict[0] = self.all_cpu_list[:mid]
        self.available_cpu_for_binding_dict[1] = self.all_cpu_list[mid:]

    def update_bind_cpu_info(self):
        numa_cfg = _read_json(CPU_BIND_CONFIG)

        for mod in MODULE_LIST:
            mod_info = numa_cfg.get(mod, "")
            id_key = f"{mod}_ID"

            if mod_info == "off":
                numa_cfg[id_key] = ""
                continue

            if not mod_info:
                mod_info = self.get_default_bind_num(len(self.all_cpu_list))

            try:
                mod_info = int(mod_info)
                if not 1 <= mod_info <= 10:
                    numa_cfg[id_key] = ""
                    LOG.warning("Module %s thread number out of range (1-10)", mod)
                    continue
            except ValueError:
                numa_cfg[id_key] = ""
                LOG.warning("Module %s thread number invalid", mod)
                continue

            cpus = self.get_module_bind_cpu_list(mod_info)
            self.bind_cpu_list.extend(cpus)
            self.bind_cpu_dict[id_key] = ",".join(map(str, cpus))

    def _get_kernel_cpu_info(self):
        remaining = sorted(set(self.all_cpu_list) - set(self.bind_cpu_list))
        mid = len(remaining) // 2
        parts = []
        if remaining[:mid]:
            parts.append(cpu_list_to_cpu_info(remaining[:mid]))
        if remaining[mid:]:
            parts.append(cpu_list_to_cpu_info(remaining[mid:]))
        return " ".join(parts)

    def finalize(self):
        info = dict(self.bind_cpu_dict)
        remaining = sorted(set(self.all_cpu_list) - set(self.bind_cpu_list))
        info[OGRAC_NUMA_INFO] = cpu_list_to_cpu_info(remaining)
        self._update_dbstor(info)

        kernel = self._get_kernel_cpu_info()
        ogracd = {"CPU_GROUP_INFO": kernel}
        mes_key = f"{MES_MODULE}_ID"
        if info.get(mes_key):
            ogracd[MES_CPU_INFO] = cpu_list_to_cpu_info(info[mes_key])
        else:
            ogracd[MES_CPU_INFO] = "-del"
        _update_ogracd_ini(ogracd)

        _write_json(CPU_CONFIG_FILE, info)
        LOG.info("cpu_config.json written to %s", CPU_CONFIG_FILE)

    def run(self):
        self.init_cpu_info()
        self.update_bind_cpu_info()
        self.finalize()


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def init_config():
    """Create cpu_bind_config.json template."""
    in_container = _cfg.get_deploy_param("ograc_in_container", "0")
    tpl = {}
    for mod in MODULE_LIST:
        if in_container != "0":
            tpl[mod] = "off"
        else:
            tpl[mod] = "off" if mod == MES_MODULE else ""
    _write_json(CPU_BIND_CONFIG, tpl)
    LOG.info("cpu_bind_config.json written to %s", CPU_BIND_CONFIG)


def update_config():
    """Detect NUMA topology and generate cpu_config.json."""
    in_container = _cfg.get_deploy_param("ograc_in_container", "0")
    if in_container == "0":
        runner = PhysicalCpuConfig()
    else:
        runner = ContainerCpuConfig()
    runner.pre_check()
    runner.run()


if __name__ == "__main__":
    try:
        if len(sys.argv) > 1 and sys.argv[1] == "init_config":
            init_config()
        else:
            update_config()
    except Exception as exc:
        LOG.error("cpu_bind failed: %s", exc)
        sys.exit(1)
