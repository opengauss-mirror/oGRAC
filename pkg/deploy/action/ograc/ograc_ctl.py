#!/usr/bin/env python3
"""oGRAC core controller."""
from __future__ import annotations

import argparse
import base64
import getpass
import glob
import json
import os
import platform
import pwd
import re
import shutil
import stat
import subprocess
import sys
import time

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
PKG_ACTION_DIR = os.path.abspath(os.path.join(CUR_DIR, ".."))
PKG_DIR = os.path.abspath(os.path.join(CUR_DIR, "../.."))

if CUR_DIR not in sys.path:
    sys.path.insert(0, CUR_DIR)

from config import get_config, get_value
from log_config import get_logger
from common.cgroup import list_ogracd_pids

LOG = get_logger()
_cfg = get_config()



def _read_json(path):
    if not os.path.isfile(path):
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _write_json(path, data):
    flags = os.O_WRONLY | os.O_TRUNC | os.O_CREAT
    modes = stat.S_IWUSR | stat.S_IRUSR
    with os.fdopen(os.open(path, flags, modes), "w") as fp:
        json.dump(data, fp)


def _read_ini(path):
    """Read ini file (KEY = VALUE format)."""
    result = {}
    if not os.path.isfile(path):
        return result
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or "=" not in line:
                continue
            key, _, val = line.partition(" = ")
            if not _:
                key, _, val = line.partition("=")
            result[key.strip()] = val.strip()
    return result


def _write_ini_params(conf_file, params):
    """Clear old params and append new params to ini file."""
    existing = []
    if os.path.isfile(conf_file):
        with open(conf_file, encoding="utf-8") as f:
            existing = f.readlines()

    param_keys = set()
    for key in params:
        escaped = re.escape(key)
        param_keys.add(re.compile(rf"^{escaped}\s*="))

    filtered = [
        line for line in existing
        if not any(pat.match(line) for pat in param_keys)
    ]

    with open(conf_file, "w", encoding="utf-8") as f:
        for line in filtered:
            f.write(line)
            if not line.endswith("\n"):
                f.write("\n")
        for key, val in params.items():
            f.write(f"{key} = {val}\n")



def _exec(cmd, timeout=1800):
    """Execute shell command."""
    proc = subprocess.Popen(
        ["bash"], shell=False,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        out_b, err_b = proc.communicate(
            input=(cmd + os.linesep).encode(), timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        return -1, "", f"Timeout {timeout}s"
    return (
        proc.returncode,
        out_b.decode(errors="replace").strip(),
        err_b.decode(errors="replace").strip(),
    )


def _exec_checked(cmd, timeout=1800, error_msg="Command failed"):
    rc, out, err = _exec(cmd, timeout)
    if rc:
        raise RuntimeError(f"{error_msg} (rc={rc}): {err or out}")
    return out


def _instance_ogracd_pids():
    return list_ogracd_pids(data_path, _cfg.deploy.ograc_user)


def _ensure_dir(path, mode=0o750):
    os.makedirs(path, exist_ok=True)
    os.chmod(path, mode)


def _safe_copy(src, dst):
    if os.path.isfile(src):
        shutil.copy2(src, dst)
    elif os.path.isdir(src):
        if os.path.exists(dst):
            shutil.rmtree(dst)
        shutil.copytree(src, dst)



INSTALL_CONFIG_FILE = os.path.join(PKG_DIR, "action", "ograc", "install_config.json")
USE_LUN = ("dss",)


class DeployParams:
    """Load deploy params from config_params_lun.json and install_config.json."""

    def __init__(self):
        dp = _cfg.deploy.raw_params
        ic = _read_json(INSTALL_CONFIG_FILE)

        self.node_id = int(dp.get("node_id", 0))
        link = dp.get("link_type", "0").strip()
        self.link_type = {"0": "TCP", "1": "RDMA", "2": "RDMA_1823"}.get(link, "TCP")
        self.deploy_mode = dp.get("deploy_mode", "").strip()
        self.db_type = dp.get("db_type", "").strip()
        self.ograc_in_container = dp.get("ograc_in_container", "0") == "1"
        self.storage_share_fs = dp.get("storage_share_fs", "").strip()
        self.namespace = dp.get("cluster_name", "test1").strip()
        self.share_logic_ip = dp.get("share_logic_ip", "127.0.0.1").strip() if self.deploy_mode == "file" else None
        self.archive_logic_ip = dp.get("archive_logic_ip", "127.0.0.1").strip()
        self.mes_type = dp.get("mes_type", "").strip()
        if self.deploy_mode == "file":
            self.mes_type = "TCP"
        self.mes_ssl_switch = dp.get("mes_ssl_switch", False)
        self.cms_ip = dp.get("cms_ip", "").strip()
        self.cms_port = dp.get("cms_port", "")
        self.ograc_port = dp.get("ograc_port", "1611")
        self.interconnect_port = dp.get("interconnect_port", "1601,1602").strip()
        self.max_arch_files_size = dp.get("MAX_ARCH_FILES_SIZE", "").strip()
        self.cluster_id = dp.get("cluster_id", "0").strip()
        self.install_type = dp.get("install_type", "0").strip()
        self.auto_tune = dp.get("auto_tune", "")

        self.use_gss = self.deploy_mode in USE_LUN

        storage_archive_fs = dp.get("storage_archive_fs", "").strip()
        if self.deploy_mode in USE_LUN:
            self.archive_location = "location=+vg3/archive"
        else:
            self.archive_location = f"location=/mnt/dbdata/remote/archive_{storage_archive_fs}"

        self.running_mode = ic.get("M_RUNING_MODE", "ogracd").strip()
        self.compatibility_mode = ic.get("DBCOMPATIBILITY", "A").strip()
        self.log_file_cfg = ic.get("l_LOG_FILE", "").strip()
        self.install_path = ic.get("R_INSTALL_PATH", "").strip()
        self.data_path = ic.get("D_DATA_PATH", "").strip()
        self.cluster_strict_check = ic.get("OG_CLUSTER_STRICT_CHECK", "FALSE")

        self.kernel_params = {}
        for i in range(100):
            val = ic.get(f"Z_KERNEL_PARAMETER{i}", "").strip()
            if val and "=" in val:
                k, _, v = val.partition("=")
                self.kernel_params[k.strip().upper()] = v.strip()



paths = _cfg.paths
ograc_home   = paths.ograc_home
ograc_root   = paths.ograc_root
install_path = paths.r_install_path
data_path    = paths.d_data_path
log_file     = paths.log_file
log_dir      = paths.log_dir
cfg_dir      = paths.ograc_cfg_dir

backup_dir   = os.path.join(paths.backup_dir, "files", "ograc")
rpm_flag     = os.path.join(ograc_home, "installed_by_rpm")
rpm_unpack   = os.path.join(ograc_home, "image", "oGRAC-RUN-LINUX-64bit")

START_STATUS_FILE = paths.start_status_file
OGRAC_CONF_FILE   = paths.ograc_conf_file
INSTALL_SCRIPT    = os.path.join(CUR_DIR, "installdb.sh")



def _read_start_status():
    return _read_json(START_STATUS_FILE)


def _update_start_status(updates):
    data = _read_start_status()
    data.update(updates)
    _write_json(START_STATUS_FILE, data)


def _decrypt_db_passwd():
    """Decode base64 password from ogsql.ini."""
    files = glob.glob(os.path.join(data_path, "cfg", "*sql.ini"))
    if not files:
        raise FileNotFoundError("No ogsql ini found in %s/cfg/" % data_path)
    with open(files[0], encoding="utf-8") as f:
        content = f.read()
    idx = content.find("=")
    if idx < 0:
        raise RuntimeError("Invalid ogsql.ini format")
    encrypt_pwd = content[idx + 1:].strip()
    return base64.b64decode(encrypt_pwd.encode("utf-8")).decode("utf-8")


def _find_ogsql_bin():
    files = glob.glob(os.path.join(install_path, "bin", "*sql"))
    if not files:
        raise FileNotFoundError("No ogsql binary found in %s/bin/" % install_path)
    return files[0]


def _execute_sql(sql, message="execute sql", timeout=600):
    """Execute SQL via ogsql sysdba."""
    ogsql = _find_ogsql_bin()
    cmd = f'source ~/.bashrc && {ogsql} / as sysdba -q -D {data_path} -c "{sql}"'
    rc, stdout, stderr = _exec(cmd, timeout=timeout)
    output = f"{stdout}{stderr}"
    if rc:
        raise RuntimeError(f"Failed to {message}: {output}")
    result = output.replace("\n", "")
    if re.match(r".*OG-\d{5}.*", result) or re.match(r".*ZS-\d{5}.*", result):
        raise RuntimeError(f"SQL error during {message}: {output}")
    return stdout


def _execute_sql_file(sql_file, timeout=3600):
    """Execute SQL file via ogsql sysdba."""
    ogsql = _find_ogsql_bin()
    cmd = f"source ~/.bashrc && {ogsql} / as sysdba -q -D {data_path} -f {sql_file}"
    rc, stdout, stderr = _exec(cmd, timeout=timeout)
    output = f"{stdout}{stderr}"
    if rc:
        raise RuntimeError(f"Failed to execute sql file {sql_file}: {output}")
    result = output.replace("\n", "")
    if re.match(r".*OG-\d{5}.*", result) or re.match(r".*ZS-\d{5}.*", result):
        raise RuntimeError(f"SQL error in {sql_file}: {output}")
    return stdout


def _check_db_open(timeout=600):
    """Poll until DB status is OPEN; raise if ogracd process is missing."""
    sql = "SELECT NAME, STATUS, OPEN_STATUS FROM DV_DATABASE"
    db_status = ""
    remaining = timeout
    while remaining > 0:
        remaining -= 10
        time.sleep(10)
        if not _instance_ogracd_pids():
            raise RuntimeError(
                "ogracd process exited unexpectedly, check log for details")
        try:
            res = _execute_sql(sql, "check db status")
        except Exception as err:
            LOG.info("check_db_status retry: %s", err)
            continue
        if "1 rows fetched" not in res:
            continue
        lines = [l for l in res.strip().split("\n") if l.strip()]
        if len(lines) >= 2:
            parts = re.split(r"\s+", lines[-2].strip())
            if len(parts) >= 2:
                db_status = parts[1].strip()
                LOG.info("DB status: %s", db_status)
                if db_status == "OPEN":
                    LOG.info("Database started successfully")
                    return
    raise RuntimeError(f"Database start timeout, last status: {db_status}")


def _check_archive_dir(dp):
    """Check archive directory."""
    if dp.db_type not in ("0", "1", "2"):
        raise RuntimeError(f"Invalid db_type: {dp.db_type}")
    if dp.db_type == "0" or dp.install_type == "reserve":
        return
    if dp.node_id == 1:
        return

    status = _read_start_status()
    if status.get("db_create_status", "default") == "done":
        return
    if dp.deploy_mode == "dss":
        return

    archive_dir = dp.archive_location.split("=")[1]
    if os.path.exists(archive_dir):
        for fname in os.listdir(archive_dir):
            if (fname.endswith(".arc") and fname.startswith("arch")) or "arch_file.tmp" in fname:
                raise RuntimeError(
                    f"Archive dir {archive_dir} has stale file: {fname}")
    else:
        raise RuntimeError(f"Archive dir {archive_dir} does not exist")
    LOG.info("Checked archive dir")


def _auto_tune_memory(c):
    """Auto-tune SGA params from physical memory."""
    threshold_gb = 31
    small_ratios = (0.20, 0.10, 0.10)
    large_ratios = (0.40, 0.10, 0.05)
    bt_ratio = 1.0 / 3
    max_bt_ratio = 0.70
    cr_divisor = 10
    min_db = 4
    min_temp = 2

    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    kb = int(line.split()[1])
                    total_gb = int(kb / 1024.0 / 1024.0 + 0.5)
                    break
            else:
                LOG.warning("MemTotal not found in /proc/meminfo, skip auto_tune")
                return
    except OSError:
        LOG.warning("Cannot read /proc/meminfo, skip auto_tune")
        return

    if total_gb < 1:
        LOG.warning("Total memory %d GB too small, skip auto_tune", total_gb)
        return

    if total_gb <= threshold_gb:
        ratios = small_ratios
        strategy = "small/medium (conservative)"
    else:
        ratios = large_ratios
        strategy = "large memory (aggressive)"

    base_db = int(total_gb * ratios[0] + 0.5)
    base_temp = int(total_gb * ratios[1] + 0.5)
    base_shared = int(total_gb * ratios[2] + 0.5)

    bt = int(base_db * bt_ratio + 0.5)
    bt = min(bt, int(base_db * max_bt_ratio + 0.5))

    db_cache = max(base_db - bt, min_db)
    temp_buffer = max(base_temp + bt, min_temp)
    shared_pool = base_shared
    cr_pool_mb = int(bt * 1024 / cr_divisor + 0.5)

    LOG.info("auto_tune: total=%dGB strategy=%s → DATA_BUFFER=%dG TEMP_BUFFER=%dG "
             "SHARED_POOL=%dG CR_POOL=%dM",
             total_gb, strategy, db_cache, temp_buffer, shared_pool, cr_pool_mb)

    c["DATA_BUFFER_SIZE"] = f"{db_cache}G"
    c["TEMP_BUFFER_SIZE"] = f"{temp_buffer}G"
    c["SHARED_POOL_SIZE"] = f"{shared_pool}G"
    c["CR_POOL_SIZE"] = f"{cr_pool_mb}M"


def _parse_size_bytes(val):
    """Parse size string (e.g. 200G, 110M) to bytes; return 0 if invalid."""
    if not isinstance(val, str) or len(val) < 2:
        return 0
    unit = val[-1].upper()
    num = val[:-1]
    if not num.isdigit() or unit not in ("G", "M", "K"):
        return 0
    multiplier = {"G": 1 << 30, "M": 1 << 20, "K": 1 << 10}
    return int(num) * multiplier[unit]


def _check_sga_memory(configs, in_container=False):
    """Validate SGA buffer size does not exceed available memory."""
    if in_container:
        return

    sga_keys = ("DATA_BUFFER_SIZE", "TEMP_BUFFER_SIZE",
                "SHARED_POOL_SIZE", "LOG_BUFFER_SIZE")
    sga_total = sum(_parse_size_bytes(str(configs.get(k, ""))) for k in sga_keys)

    min_sga = 114 * (1 << 20)
    if sga_total < min_sga:
        raise RuntimeError(
            f"SGA buffer total ({sga_total / (1 << 20):.0f}MB) is less than "
            f"minimum requirement (114MB)")

    try:
        with open("/proc/meminfo") as f:
            avail_kb = 0
            for line in f:
                if any(line.startswith(k) for k in
                       ("MemFree:", "Buffers:", "Cached:", "SwapCached:")):
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        avail_kb += int(parts[1])
    except OSError:
        LOG.warning("Cannot read /proc/meminfo, skip SGA memory check")
        return

    avail_bytes = avail_kb * 1024
    if sga_total > avail_bytes:
        sga_gb = sga_total / (1 << 30)
        avail_gb = avail_bytes / (1 << 30)
        raise RuntimeError(
            f"SGA buffer total ({sga_gb:.1f}GB) exceeds available memory "
            f"({avail_gb:.1f}GB). Consider setting auto_tune=1 or reducing "
            f"DATA_BUFFER_SIZE/TEMP_BUFFER_SIZE/SHARED_POOL_SIZE manually.")


def _detect_cpu_group_info(use_gss):
    """Detect NUMA topology, return CPU_GROUP_INFO string (e.g. '0-23 24-47')."""
    if not os.path.exists("/usr/bin/lscpu"):
        LOG.warning("lscpu not found, skip CPU_GROUP_INFO detection")
        return ""

    rc, result, _ = _exec("/usr/bin/lscpu | grep -i 'NUMA node(s)'")
    if rc:
        LOG.warning("Failed to get NUMA node count")
        return ""

    parts = result.strip().split(":")
    if len(parts) != 2 or not parts[1].strip().isdigit():
        LOG.warning("Unexpected lscpu NUMA output: %s", result.strip())
        return ""

    numa_count = int(parts[1].strip())
    numa_info = ""
    for i in range(numa_count):
        rc2, ans, _ = _exec(f'/usr/bin/lscpu | grep -i "NUMA node{i}"')
        ans_parts = ans.strip().split(":")
        if len(ans_parts) != 2:
            LOG.warning("Failed to get NUMA node%d info: %s", i, ans.strip())
            return ""
        numa_str = ans_parts[1].strip()
        if platform.machine() == "aarch64" and i == 0:
            numa_id_parts = numa_str.split("-")
            last_id = numa_id_parts[-1]
            if last_id.isdigit() and int(last_id) >= 16 and use_gss:
                numa_str = f"0-1,6-11,16-{last_id}"
        numa_info += numa_str + " "

    numa_info = numa_info.strip()
    if numa_info:
        LOG.info("Detected CPU_GROUP_INFO: %s", numa_info)
    return numa_info


def _build_ogracd_configs(dp):
    """Build full ogracd.ini config dict."""
    is_uc = dp.mes_type in ("UC", "UC_RDMA")
    is_file_mode = dp.deploy_mode == "file"
    node_addr = dp.cms_ip.split(";")[dp.node_id] if dp.cms_ip else "127.0.0.1"

    c = {
        "CHECKPOINT_IO_CAPACITY": 4096,
        "DTC_CKPT_NOTIFY_TASK_RATIO": 0.032,
        "DTC_CLEAN_EDP_TASK_RATIO": 0.032,
        "DTC_TXN_INFO_TASK_RATIO": 0.125,
        "BUFFER_PAGE_CLEAN_PERIOD": 1,
        "BUFFER_LRU_SEARCH_THRE": 40,
        "BUFFER_PAGE_CLEAN_RATIO": 0.1,
        "_DEADLOCK_DETECT_INTERVAL": 1000,
        "INTERCONNECT_CHANNEL_NUM": 3 if is_uc and not is_file_mode else 32,
        "_UNDO_AUTO_SHRINK": "FALSE",
        "_CHECKPOINT_TIMED_TASK_DELAY": 100,
        "DBWR_PROCESSES": 8,
        "SESSIONS": 18432,
        "CLUSTER_DATABASE": "TRUE",
        "_DOUBLEWRITE": "TRUE" if is_file_mode else "FALSE",
        "TEMP_BUFFER_SIZE": "25G",
        "DATA_BUFFER_SIZE": "200G",
        "SHARED_POOL_SIZE": "25G",
        "LOG_BUFFER_COUNT": 16,
        "LOG_BUFFER_SIZE": "110M",
        "MES_POOL_SIZE": 16384,
        "TIMED_STATS": "TRUE",
        "SQL_STAT": "TRUE",
        "MES_ELAPSED_SWITCH": "TRUE",
        "_LOG_LEVEL": 7,
        "OGRAC_TASK_NUM": 256,
        "REACTOR_THREAD_NUM": 6,
        "_INDEX_BUFFER_SIZE": "1G",
        "_DISABLE_SOFT_PARSE": "FALSE",
        "_ENABLE_QOS": "FALSE",
        "USE_NATIVE_DATATYPE": "TRUE",
        "_PREFETCH_ROWS": 100,
        "CHECKPOINT_PERIOD": 1,
        "CHECKPOINT_PAGES": 200000,
        "REACTOR_THREADS": 1,
        "OPTIMIZED_WORKER_THREADS": 2000,
        "MAX_WORKER_THREADS": 2000,
        "STATS_LEVEL": "TYPICAL",
        "BUF_POOL_NUM": 32,
        "PAGE_CHECKSUM": "TYPICAL",
        "CR_MODE": "PAGE",
        "_AUTO_INDEX_RECYCLE": "ON",
        "DEFAULT_EXTENTS": 128,
        "TEMP_POOL_NUM": 8,
        "UNDO_RETENTION_TIME": 600,
        "CR_POOL_SIZE": "1G",
        "CR_POOL_COUNT": 32,
        "VARIANT_MEMORY_AREA_SIZE": "2G",
        "_VMP_CACHES_EACH_SESSION": 50,
        "_PRIVATE_KEY_LOCKS": 128,
        "_PRIVATE_ROW_LOCKS": 128,
        "_UNDO_SEGMENTS": 1024,
        "_UNDO_ACTIVE_SEGMENTS": 64,
        "USE_LARGE_PAGES": "FALSE",
        "OGSTORE_MAX_OPEN_FILES": 40960,
        "REPLAY_PRELOAD_PROCESSES": 0,
        "LOG_REPLAY_PROCESSES": 64,
        "_LOG_MAX_FILE_SIZE": "160M",
        "_LOG_BACKUP_FILE_COUNT": 6,
        "RECYCLEBIN": "FALSE",
        "LARGE_POOL_SIZE": "1G",
        "JOB_QUEUE_PROCESSES": 100,
        "MAX_COLUMN_COUNT": 4096,
        "INSTANCE_ID": dp.node_id,
        "INTERCONNECT_PORT": dp.interconnect_port or "1601,1602",
        "INTERCONNECT_TYPE": dp.mes_type if is_uc and not is_file_mode else "TCP",
        "INTERCONNECT_BY_PROFILE": "FALSE",
        "INSTANCE_NAME": "ograc",
        "ENABLE_SYSDBA_LOGIN": "TRUE",
        "REPL_AUTH": "FALSE",
        "REPL_SCRAM_AUTH": "TRUE",
        "ENABLE_ACCESS_DC": "FALSE",
        "REPLACE_PASSWORD_VERIFY": "TRUE",
        "PAGE_CLEAN_MODE": "ALL",
        "ENABLE_IDX_KEY_LEN_CHECK": "FALSE",
        "EMPTY_STRING_AS_NULL": "TRUE",
        "_CHECKPOINT_MERGE_IO": "FALSE",
        "ENABLE_DBSTOR_BATCH_FLUSH": "TRUE",
        "_BUFFER_PAGE_CLEAN_WAIT_TIMEOUT": "1",
        "_OPTIM_SUBQUERY_REWRITE": "TRUE",
        "LOG_HOME": log_dir,
        "INTERCONNECT_ADDR": dp.cms_ip,
        "LSNR_ADDR": f"127.0.0.1,{node_addr}",
        "LSNR_PORT": str(dp.ograc_port),
        "MES_SSL_SWITCH": str(dp.mes_ssl_switch).upper(),
        "ARCHIVE_DEST_1": dp.archive_location,
        "MAX_ARCH_FILES_SIZE": dp.max_arch_files_size,
        "CLUSTER_ID": dp.cluster_id,
    }

    if dp.cluster_strict_check in ("FALSE", "TRUE"):
        c["OG_CLUSTER_STRICT_CHECK"] = dp.cluster_strict_check

    c.update(dp.kernel_params)

    cpu_group = _detect_cpu_group_info(dp.use_gss)
    if cpu_group:
        c["CPU_GROUP_INFO"] = cpu_group

    if dp.use_gss:
        c["CONTROL_FILES"] = "(+vg1/ctrl1, +vg1/ctrl2, +vg1/ctrl3)"
        c["ENABLE_DSS"] = "TRUE"
        c["SHARED_PATH"] = "+vg1"
        c["FILE_OPTIONS"] = "ASYNCH"
        dss_home = os.path.join(ograc_home, "dss")
        c["OGSTORE_INST_PATH"] = f"UDS:{dss_home}/.dss_unix_d_socket"
    else:
        c["CONTROL_FILES"] = ", ".join(
            os.path.join(data_path, f"data/ctrl{i}") for i in (1, 2, 3))
        c["SHARED_PATH"] = f"/mnt/dbdata/remote/storage_{dp.storage_share_fs}/data"
        c["FILE_OPTIONS"] = "FULLDIRECTIO"

    if dp.auto_tune == "1":
        _auto_tune_memory(c)

    _check_sga_memory(c, in_container=dp.ograc_in_container)

    return c


def _prompt_sys_password():
    if not sys.stdin.isatty():
        raise RuntimeError("password should be set in interactive terminal.")
    prompt = "please input ograc password: "
    confirm_prompt = "please confirm the password: "
    pwd1 = getpass.getpass(prompt)
    if not pwd1:
        raise RuntimeError("password cannot be empty.")
    pwd2 = getpass.getpass(confirm_prompt)
    if pwd1 != pwd2:
        raise RuntimeError("the password entered twice does not match, please re-execute the installation.")
    return pwd1


def _write_cluster_conf(dp, ogracd_configs, user, group, password):
    conf_file = os.path.join(data_path, "cfg", "cluster.ini")
    _exec(f"echo >> {conf_file}")

    node_ips = re.split(r"[;,]", ogracd_configs.get("INTERCONNECT_ADDR", ""))
    if len(node_ips) < 2:
        node_ips.append("127.0.0.1")

    cluster_size = 1 if dp.running_mode.lower() == "ogracd" else 2
    user_home = pwd.getpwnam(user).pw_dir

    params = {
        "LSNR_PORT[0]": dp.ograc_port,
        "LSNR_PORT[1]": dp.ograc_port,
        "REPORT_FILE": log_file,
        "STATUS_LOG": os.path.join(data_path, "log", "ogracstatus.log"),
        "LD_LIBRARY_PATH": os.environ.get("LD_LIBRARY_PATH", ""),
        "USER_HOME": user_home,
        "USE_GSS": dp.use_gss,
        "CLUSTER_SIZE": cluster_size,
        "NODE_ID": dp.node_id,
        "NODE_IP[0]": node_ips[0],
        "NODE_IP[1]": node_ips[1] if len(node_ips) > 1 else "127.0.0.1",
        "CMS_PORT[0]": dp.cms_port,
        "CMS_PORT[1]": dp.cms_port,
        "LSNR_NODE_IP[0]": node_ips[0],
        "LSNR_NODE_IP[1]": node_ips[1] if len(node_ips) > 1 else "127.0.0.1",
        "USER": user,
        "GROUP": group,
        "DATA": data_path,
        "CREAT_DB_FILE": "",
        "INSTALL_PATH": install_path,
        "RUNNING_MODE": dp.running_mode,
        "LOG_HOME": ogracd_configs.get("LOG_HOME", log_dir),
        "SYS_PASSWORD": password or "",
    }

    _write_ini_params(conf_file, params)
    params_for_json = {**params, "SYS_PASSWORD": ""}
    _write_json(OGRAC_CONF_FILE, params_for_json)


def _encrypt_password(plain_password):
    """Encrypt password with ogencrypt; raises on failure."""
    ogencrypt_bin = os.path.join(install_path, "bin", "ogencrypt")
    if not os.path.isfile(ogencrypt_bin):
        raise RuntimeError(
            f"ogencrypt not found at {ogencrypt_bin}, "
            "cannot encrypt _SYS_PASSWORD")

    cmd = f"source ~/.bashrc && {ogencrypt_bin} -e PBKDF2"
    proc = subprocess.Popen(
        ["bash"], shell=False,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    pw = plain_password.encode()
    sep = os.linesep.encode()
    proc.stdin.write(cmd.encode())
    proc.stdin.write(sep)
    proc.stdin.write(pw)
    proc.stdin.write(sep)
    proc.stdin.write(pw)
    proc.stdin.write(sep)
    try:
        out_b, err_b = proc.communicate(timeout=60)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise RuntimeError("ogencrypt timed out")

    stdout = out_b.decode(errors="replace")
    stderr = err_b.decode(errors="replace")
    if proc.returncode:
        raise RuntimeError(
            f"Failed to encrypt _SYS_PASSWORD (rc={proc.returncode}): {stderr}")

    lines = stdout.split(os.linesep)
    for line in lines:
        if "Cipher:" in line:
            cipher = line.split(":", 1)[1].strip()
            if cipher:
                return cipher
    raise RuntimeError(
        f"Failed to parse ogencrypt output, no Cipher found.\n"
        f"stdout: {stdout}\nstderr: {stderr}")


def _set_user_env(user):
    """Set user env vars (profile + os.environ)."""
    user_home = pwd.getpwnam(user).pw_dir
    profile = os.path.join(user_home, ".bashrc")
    if os.path.isfile(profile):
        env_lines = [
            f'export OGDB_HOME="{install_path}"',
            f'export PATH="{install_path}/bin":$PATH',
            f'export LD_LIBRARY_PATH="{install_path}/lib":"{install_path}/add-ons":$LD_LIBRARY_PATH',
            f'export OGDB_DATA="{data_path}"',
        ]
        with open(profile, "a") as f:
            for line in env_lines:
                f.write(line + os.linesep)

    os.environ["OGDB_HOME"] = install_path
    os.environ["OGDB_DATA"] = data_path
    os.environ["PATH"] = f"{install_path}/bin:{os.environ.get('PATH', '')}"
    lib_path = f"{install_path}/lib:{install_path}/add-ons"
    os.environ["LD_LIBRARY_PATH"] = f"{lib_path}:{os.environ.get('LD_LIBRARY_PATH', '')}"
    for var in ("OGSQL_SSL_CA", "OGSQL_SSL_CERT", "OGSQL_SSL_KEY",
                "OGSQL_SSL_MODE", "OGSQL_SSL_KEY_PASSWD"):
        os.environ[var] = ""


def _prepare_data_dir(dp, user, group):
    """Create data dir structure and move cfg."""
    user_info = f"{user}:{group}"
    _exec(f"chmod 700 {data_path}")

    for sub in ("log", "archive_log", "trc", "tmp"):
        os.makedirs(os.path.join(data_path, sub), 0o700, exist_ok=True)

    data_dir = os.path.join(data_path, "data")
    if dp.use_gss:
        os.makedirs(data_dir, 0o700, exist_ok=True)
    else:
        mount_storage = f"/mnt/dbdata/remote/storage_{dp.storage_share_fs}/data"
        if not os.path.exists(data_dir):
            os.symlink(mount_storage, data_dir)

    src_cfg = os.path.join(install_path, "cfg")
    dst_cfg = os.path.join(data_path, "cfg")
    if os.path.isdir(src_cfg) and not os.path.exists(dst_cfg):
        rc, _, err = _exec(f"mv -i {src_cfg} {data_path}")
        if rc:
            raise RuntimeError(f"Failed to move cfg dir: {err}")

    ogsql_ini = os.path.join(dst_cfg, "ogsql.ini")
    if not os.path.exists(ogsql_ini):
        open(ogsql_ini, "a").close()

    for conf_name in ("ogracd.ini", "cms.ini", "oghba.conf", "ogsql.ini"):
        p = os.path.join(dst_cfg, conf_name)
        if os.path.isfile(p):
            os.chmod(p, 0o600)

    _exec(f"chown -hR {user_info} {data_path}")


def _add_hba_whitelist(dp, ogracd_configs):
    """Add INTERCONNECT_ADDR whitelist to oghba.conf."""
    cthba_file = os.path.join(data_path, "cfg", "oghba.conf")
    if not os.path.isfile(cthba_file):
        return
    addr_list = []
    interconnect = ogracd_configs.get("INTERCONNECT_ADDR", "")
    for item in re.split(r"[;,]", interconnect):
        item = item.strip()
        if item and item not in ("127.0.0.1", "::1"):
            addr_list.append(item)
    if not addr_list:
        return
    cmd = ""
    for addr in addr_list:
        cmd += f"echo 'host * {addr}' >> {cthba_file}; "
    if cmd:
        _exec(cmd.rstrip("; "))


def _start_ogracd_process(dp, ogracd_configs):
    """Invoke installdb.sh to start ogracd process."""
    status = _read_start_status()
    db_create_done = status.get("db_create_status", "default") == "done"

    if dp.node_id == 1:
        start_mode = "open"
    elif dp.install_type == "reserve":
        start_mode = "open"
    elif db_create_done:
        start_mode = "open"
    else:
        start_mode = "nomount"

    script = INSTALL_SCRIPT
    running_mode = dp.running_mode.lower()
    cmd = f"sh {script} -P ogracd -M {start_mode} -T {running_mode} >> {log_file} 2>&1"
    LOG.info("Starting ogracd: mode=%s, running=%s", start_mode, running_mode)

    rc, stdout, stderr = _exec(cmd, timeout=1800)
    if rc:
        output = (stdout + stderr).replace(str(ogracd_configs.get("_SYS_PASSWORD", "")), "***")
        raise RuntimeError(f"Failed to start ogracd: {output}")

    consecutive_missing = 0
    for i in range(300):
        time.sleep(3)
        pids = _instance_ogracd_pids()
        if pids:
            LOG.info("ogracd process detected (pid=%s)", pids[0])
            return
        consecutive_missing += 1
        if consecutive_missing >= 10:
            raise RuntimeError(
                "ogracd process not found 30s after startup script returned, "
                "check ogracd run log for details")
    raise RuntimeError("ogracd process not found after startup")


def _patch_create_sql(sql_file, dp):
    """Patch create-db SQL file paths per deploy mode."""
    redo_num = _cfg.deploy.get("redo_num", "")
    redo_size = _cfg.deploy.get("redo_size", "")
    if redo_num and redo_size:
        _patch_redo_config(sql_file, int(redo_num), redo_size)

    if dp.use_gss:
        _sed_replace(sql_file, "dbfiles1", "+vg1")
        _sed_replace(sql_file, "dbfiles2", "+vg2")
        _sed_replace(sql_file, "dbfiles3", "+vg2")
    else:
        db_data = os.path.join(data_path, "data").replace("/", r"\/")
        _sed_replace(sql_file, "dbfiles1", db_data)
        _sed_replace(sql_file, "dbfiles2", db_data)
        _sed_replace(sql_file, "dbfiles3", db_data)


def _sed_replace(sql_file, pattern, replacement):
    rc, _, err = _exec(f"sed -i 's/{pattern}/{replacement}/g' {sql_file}")
    if rc:
        raise RuntimeError(f"sed failed on {sql_file}: replace {pattern} -> {replacement}: {err}")


def _patch_redo_config(sql_file, redo_num, redo_size):
    """Adjust redo count/size per user config (call before path sed)."""
    with open(sql_file, "r", encoding="utf-8") as f:
        content = f.read()
    matches = re.findall(r"logfile (\(.*\n{0,}.*\))", content)
    if not matches:
        return
    s = []
    for i in range(1, redo_num * 2 + 1):
        idx = f"{i:02d}" if i != 10 else "0a"
        s.append(f"'dbfiles3/redo{idx}.dat' size {redo_size}")
    node0 = ", ".join(s[:redo_num])
    node1 = ", ".join(s[redo_num:])
    for m in matches:
        content = content.replace(m, "(%s)")
    content = content % (node0, node1)
    flags = os.O_WRONLY | os.O_TRUNC | os.O_CREAT
    modes = stat.S_IWUSR | stat.S_IRUSR
    with os.fdopen(os.open(sql_file, flags, modes), "w", encoding="utf-8") as f:
        f.write(content)


def _create_database(dp, ogracd_configs):
    """Create DB on first start (node0 only)."""
    if dp.node_id != 0:
        return

    status = _read_start_status()
    if status.get("db_create_status", "default") != "default":
        return

    _update_start_status({"db_create_status": "creating"})

    mode = dp.compatibility_mode
    if mode == "B":
        sql_dir = os.path.join(install_path, "admin", "dialect_b_scripts")
    elif mode == "C":
        sql_dir = os.path.join(install_path, "admin", "dialect_c_scripts")
    elif mode == "A":
        sql_dir = os.path.join(install_path, "admin", "scripts")
    else:
        raise ValueError(f"Only Support A or B or C compatibility mode, got '{mode}'.")

    if dp.running_mode.lower() == "ogracd_in_cluster":
        base_name = "create_cluster_database.sample.sql"
    else:
        base_name = "create_database.sample.sql"

    db_type = _cfg.deploy.get("db_type", "1").strip()
    if db_type in ("0", "1", "2"):
        type_map = {
            "0": base_name.replace(".sample.", ".lun."),
            "1": base_name,
            "2": base_name.replace("cluster_", "") if "cluster_" in base_name else base_name,
        }
        base_name = type_map.get(db_type, base_name)

    sql_file = os.path.join(sql_dir, base_name)
    if not os.path.isfile(sql_file):
        raise FileNotFoundError(f"SQL file not found: {sql_file}")

    _patch_create_sql(sql_file, dp)

    LOG.info("Creating database with dbcompatibility '%s', sql: %s", dp.compatibility_mode, sql_file)
    _execute_sql_file(sql_file)
    _update_start_status({"db_create_status": "done"})
    LOG.info("Database created successfully")


def _create_3rd_pkg():
    """Run 3rd-party package creation script after DB create."""
    sql_file = os.path.join(install_path, "admin", "scripts", "create_3rd_pkg.sql")
    if not os.path.isfile(sql_file):
        LOG.warning("create_3rd_pkg.sql not found, skipping")
        return
    LOG.info("Creating third package ...")
    _execute_sql_file(sql_file)
    LOG.info("Creating third package succeed.")


def action_pre_install():
    """pre_install logic."""
    LOG.info("===== pre_install =====")

    if platform.system() != "Linux":
        raise RuntimeError(f"Unsupported platform: {platform.system()}")

    _ensure_dir(log_dir, 0o750)

    dp = DeployParams()
    valid_modes = {"ogracd", "ogracd_in_cluster"}
    if dp.running_mode.lower() not in valid_modes:
        raise RuntimeError(f"Invalid running mode: {dp.running_mode}")
    if dp.node_id not in (0, 1):
        raise RuntimeError(f"Invalid node id: {dp.node_id}")
    if dp.running_mode.lower() == "ogracd" and dp.node_id == 1:
        raise RuntimeError("Node id 1 can only run in cluster mode")

    LOG.info("pre_install done")


def action_install():
    """install logic."""
    LOG.info("===== install =====")

    dp = DeployParams()
    install_type = dp.install_type
    user = _cfg.deploy.ograc_user
    group = _cfg.deploy.ograc_group
    user_info = f"{user}:{group}"

    if os.path.isdir(data_path):
        shutil.rmtree(data_path)
    _ensure_dir(install_path, 0o750)
    _ensure_dir(data_path, 0o750)
    tmp_dir = os.path.dirname(data_path)
    os.chmod(tmp_dir, 0o750)
    _ensure_dir(log_dir, 0o750)

    if not os.path.isfile(rpm_flag):
        for subdir in ("add-ons", "bin", "lib", "admin", "cfg"):
            src = os.path.join(rpm_unpack, subdir)
            dst = os.path.join(install_path, subdir)
            if os.path.exists(src):
                _safe_copy(src, dst)
        pkg_xml = os.path.join(rpm_unpack, "package.xml")
        if os.path.isfile(pkg_xml):
            shutil.copy2(pkg_xml, os.path.join(install_path, "package.xml"))
        cms_bin = os.path.join(install_path, "bin", "cms")
        if os.path.exists(cms_bin):
            if os.path.isdir(cms_bin):
                shutil.rmtree(cms_bin)
            else:
                os.remove(cms_bin)
        LOG.info("RPM files copied")
    _exec(f"chmod 700 -R {install_path}")

    _ensure_dir(cfg_dir, 0o750)
    _write_json(START_STATUS_FILE, {
        "start_status": "default",
        "db_create_status": "default",
        "ever_started": False,
    })

    _exec(f"chown {user_info} -hR {install_path}")

    _set_user_env(user)

    _prepare_data_dir(dp, user, group)

    ogracd_configs = _build_ogracd_configs(dp)

    sys_password = ""
    pw_file = os.environ.get("OGRAC_SYS_PASSWORD_FILE")
    if pw_file and os.path.isfile(pw_file):
        try:
            with open(pw_file, "r", encoding="utf-8") as f:
                sys_password = f.read().strip()
        except OSError as e:
            raise RuntimeError(f"failed to read SYS password file {pw_file}: {e}") from e
    else:
        sys_password = _prompt_sys_password()

    if install_type != "override":
        for fname in ("ogracd.ini", "ogsql.ini"):
            src = os.path.join(backup_dir, fname)
            dst = os.path.join(data_path, "cfg", fname)
            _ensure_dir(os.path.dirname(dst), 0o750)
            if os.path.isfile(src):
                shutil.copy2(src, dst)

        backup_cfg_json = os.path.join(backup_dir, "ograc_config.json")
        if os.path.isfile(backup_cfg_json):
            _ensure_dir(cfg_dir, 0o750)
            shutil.copy2(backup_cfg_json, cfg_dir)

    if sys_password and not dp.ograc_in_container:
        ogracd_configs["_SYS_PASSWORD"] = _encrypt_password(sys_password)
    elif sys_password:
        ogracd_configs["_SYS_PASSWORD"] = sys_password

    if dp.mes_ssl_switch:
        cert_pwd = get_value("cert_encrypt_pwd")
        if cert_pwd:
            ogracd_configs["MES_SSL_KEY_PWD"] = base64.b64encode(
                cert_pwd.encode("UTF-8")).decode("UTF-8")

    ogracd_ini_path = os.path.join(data_path, "cfg", "ogracd.ini")
    _write_ini_params(ogracd_ini_path, ogracd_configs)

    _add_hba_whitelist(dp, ogracd_configs)

    _write_cluster_conf(dp, ogracd_configs, user, group, sys_password)

    if install_type != "override":
        backup_cfg_dir_path = os.path.join(backup_dir, "cfg")
        data_cfg_path = os.path.join(data_path, "cfg")
        if os.path.isdir(backup_cfg_dir_path):
            if os.path.isdir(data_cfg_path):
                shutil.rmtree(data_cfg_path)
            shutil.copytree(backup_cfg_dir_path, data_cfg_path)
        backup_cfg_json = os.path.join(backup_dir, "ograc_config.json")
        if os.path.isfile(backup_cfg_json):
            shutil.copy2(backup_cfg_json, os.path.join(CUR_DIR, "ograc_config.json"))

    _exec(f"chown -hR {user_info} {data_path}")
    _exec(f"chmod 700 -R {data_path}/cfg")

    LOG.info("install done")


def action_start():
    """start logic."""
    LOG.info("===== start =====")

    dp = DeployParams()

    db_create_status = _read_start_status().get("db_create_status", "default")
    if db_create_status == "creating":
        raise RuntimeError(
            "Failed to create namespace at last startup, "
            "please reinstall after uninstalling and modifying namespace.")

    start_status = _read_start_status().get("start_status", "default")

    def _ogracd_running():
        for _ in range(3):
            time.sleep(1)
        return bool(_instance_ogracd_pids())

    if start_status == "starting" and not _ogracd_running():
        LOG.info("Last startup interrupted, stopping first")
        action_stop()

    if start_status == "started":
        if _ogracd_running():
            LOG.info("ogracd already started")
            return
        LOG.info("Status is started but no process, restarting")
        action_stop()

    start_mode_arg = ""
    if len(sys.argv) > 2:
        start_mode_arg = sys.argv[2]
    if start_mode_arg == "standby":
        _update_start_status({"db_create_status": "done"})


    _update_start_status({"start_status": "starting"})

    _check_archive_dir(dp)

    ogracd_ini = _read_ini(os.path.join(data_path, "cfg", "ogracd.ini"))
    enable_sysdba = ogracd_ini.get("ENABLE_SYSDBA_LOGIN", "FALSE").upper() == "TRUE"

    ograc_conf = _read_json(OGRAC_CONF_FILE)
    ogracd_configs_for_start = {
        "LOG_HOME": ograc_conf.get("LOG_HOME", log_dir),
        "_SYS_PASSWORD": ograc_conf.get("SYS_PASSWORD", ""),
        "INTERCONNECT_ADDR": ograc_conf.get("INTERCONNECT_ADDR", dp.cms_ip),
    }

    try:
        _start_ogracd_process(dp, ogracd_configs_for_start)

        if dp.node_id == 0:
            LOG.info("Waiting for ogracd threads...")
            for _ in range(4):
                time.sleep(5)
                if not _instance_ogracd_pids():
                    raise RuntimeError(
                        "ogracd process exited during initialization, "
                        "check ogracd run log for details")
            _create_database(dp, ogracd_configs_for_start)
            _create_3rd_pkg()

        _check_db_open(timeout=600)

        _update_start_status({
            "start_status": "started",
            "ever_started": True,
        })

        ogracd_pids = _instance_ogracd_pids()
        if ogracd_pids:
            pid = ogracd_pids[0]
            coredump_path = f"/proc/{pid}/coredump_filter"
            rc2, _, err2 = _exec(f"echo 0x6f > {coredump_path}")
            if rc2:
                LOG.warning("Failed to set coredump_filter: %s", err2)
            else:
                LOG.info("Set coredump_filter successfully")

        admin_dir = os.path.join(install_path, "admin")
        if os.path.isdir(admin_dir):
            _exec(f"find '{admin_dir}' -type f | xargs chmod 400")

    except Exception as error:
        LOG.error("Start failed: %s", error)
        raise

    LOG.info("start done")


def action_stop():
    """stop logic."""
    LOG.info("===== stop =====")

    start_status = _read_start_status().get("start_status", "default")

    ogracd_pids = _instance_ogracd_pids()
    if not ogracd_pids:
        if start_status == "default":
            LOG.info("ograc status is default, not started")
            return
        LOG.info("No ogracd process found, treat stop as success")
        return

    ograc_conf = _read_json(OGRAC_CONF_FILE)
    r_install = ograc_conf.get("INSTALL_PATH", install_path)
    d_data = ograc_conf.get("DATA", data_path)
    lsnr_addr = ograc_conf.get("LSNR_NODE_IP[0]",
                               ograc_conf.get("INTERCONNECT_ADDR", "127.0.0.1"))
    if "," in lsnr_addr:
        lsnr_addr = lsnr_addr.split(",")[0]
    if ";" in lsnr_addr:
        lsnr_addr = lsnr_addr.split(";")[0]
    lsnr_port = ograc_conf.get("LSNR_PORT[0]",
                               ograc_conf.get("LSNR_PORT", "1611"))

    shutdown_script = os.path.join(r_install, "bin", "shutdowndb.sh")
    if not os.path.isfile(shutdown_script):
        LOG.warning("shutdowndb.sh not found, trying kill")
        for pid in _instance_ogracd_pids():
            _exec(f"kill {pid} 2>/dev/null || true")
        time.sleep(5)
        LOG.info("stop done (kill)")
        return

    lib_path = ":".join((
        os.path.join(r_install, "lib"),
        os.path.join(r_install, "add-ons"),
        "${LD_LIBRARY_PATH:-}",
    ))
    cmd = (
        f'export PATH="{os.path.join(r_install, "bin")}:$PATH"; '
        f'export LD_LIBRARY_PATH="{lib_path}"; '
        f'export OGDB_HOME="{r_install}"; '
        f'export OGDB_DATA="{d_data}"; '
        f'"{shutdown_script}" -h {lsnr_addr} -p {lsnr_port}'
        f" -w -m immediate -D {d_data} -T 1800"
    )
    LOG.info("Stopping database: %s", cmd)
    rc, stdout, stderr = _exec(cmd, timeout=1800)
    if rc:
        raise RuntimeError(f"Failed to stop database (rc={rc}): {stderr or stdout}")

    LOG.info("stop done")


def action_check_status():
    """check_status logic."""
    LOG.info("===== check_status =====")
    _check_db_open(timeout=300)
    LOG.info("check_status done")


def action_uninstall():
    """uninstall logic."""
    LOG.info("===== uninstall =====")

    user = _cfg.deploy.ograc_user

    install_cfg_file = os.path.join(CUR_DIR, "install_config.json")
    d_data = data_path
    if os.path.isfile(install_cfg_file):
        try:
            with open(install_cfg_file, encoding="utf-8") as f:
                d_data = json.load(f).get("D_DATA_PATH", data_path)
        except Exception:
            pass

    rc, out, _ = _exec(
        f'ps -fu {user} | grep "\\-D {d_data}" | grep -vE "(grep|defunct)" | wc -l'
    )
    if rc == 0 and out.strip().isdigit() and int(out.strip()) >= 1:
        raise RuntimeError("ograc process still running, stop before uninstall")

    user_home = pwd.getpwnam(user).pw_dir
    profile = os.path.join(user_home, ".bashrc")
    if os.path.isfile(profile):
        for pattern in ("OGDB_HOME", "OGDB_DATA", "OGRACLOG"):
            _exec(f'sed -i "/^export {pattern}=/d" {profile}')

    data_log = os.path.join(d_data, "log")
    if os.path.isdir(data_log):
        dst_log = os.path.join(log_dir, "ograc_start_log")
        _ensure_dir(dst_log, 0o750)
        _exec(f"yes | cp -arf {data_log} {dst_log}")

    if os.path.isdir(d_data):
        shutil.rmtree(d_data)

    LOG.info("uninstall done")


def action_backup():
    """backup logic."""
    LOG.info("===== backup =====")

    _ensure_dir(backup_dir, 0o700)

    for fname in ("ogracd.ini", "ogsql.ini"):
        src = os.path.join(data_path, "cfg", fname)
        if os.path.isfile(src):
            shutil.copy2(src, backup_dir)

    cfg_src = os.path.join(data_path, "cfg")
    cfg_dst = os.path.join(backup_dir, "cfg")
    if os.path.isdir(cfg_src):
        if os.path.isdir(cfg_dst):
            shutil.rmtree(cfg_dst)
        shutil.copytree(cfg_src, cfg_dst)

    ograc_cfg_json = os.path.join(cfg_dir, "ograc_config.json")
    if os.path.isfile(ograc_cfg_json):
        shutil.copy2(ograc_cfg_json, backup_dir)

    LOG.info("backup done")


def action_restore():
    """Restore ograc config from backup dir."""
    LOG.info("===== restore =====")

    if not os.path.isdir(backup_dir):
        raise RuntimeError(f"Backup directory not found: {backup_dir}")

    for fname in ("ogracd.ini", "ogsql.ini"):
        src = os.path.join(backup_dir, fname)
        dst = os.path.join(data_path, "cfg", fname)
        _ensure_dir(os.path.dirname(dst), 0o750)
        if os.path.isfile(src):
            shutil.copy2(src, dst)
            LOG.info("Restored %s", fname)

    backup_cfg_dir = os.path.join(backup_dir, "cfg")
    data_cfg_path = os.path.join(data_path, "cfg")
    if os.path.isdir(backup_cfg_dir):
        if os.path.isdir(data_cfg_path):
            shutil.rmtree(data_cfg_path)
        shutil.copytree(backup_cfg_dir, data_cfg_path)
        LOG.info("Restored cfg directory")

    backup_cfg_json = os.path.join(backup_dir, "ograc_config.json")
    if os.path.isfile(backup_cfg_json):
        _ensure_dir(cfg_dir, 0o750)
        shutil.copy2(backup_cfg_json, os.path.join(cfg_dir, "ograc_config.json"))
        LOG.info("Restored ograc_config.json")

    LOG.info("restore done")


def action_post_upgrade():
    """post_upgrade logic."""
    LOG.info("===== post_upgrade =====")

    try:
        db_passwd = _decrypt_db_passwd()
    except Exception as e:
        LOG.warning("decrypt_db_passwd failed (may not be needed): %s", e)
        db_passwd = None

    ic = _read_json(INSTALL_CONFIG_FILE)
    r_install = ic.get("R_INSTALL_PATH", install_path)

    LOG.info("Post upgrade check: verifying DB status...")
    _check_db_open(timeout=600)

    LOG.info("post_upgrade done")



ACTION_MAP = {
    "pre_install":    action_pre_install,
    "install":        action_install,
    "uninstall":      action_uninstall,
    "start":          action_start,
    "stop":           action_stop,
    "check_status":   action_check_status,
    "backup":         action_backup,
    "restore":        action_restore,
    "post_upgrade":   action_post_upgrade,
}


def main():
    parser = argparse.ArgumentParser(description="oGRAC controller")
    parser.add_argument("action", type=str, choices=list(ACTION_MAP.keys()) + [
        "pre_upgrade", "upgrade_backup", "upgrade", "rollback", "init_container",
    ])
    args, _ = parser.parse_known_args()

    fn = ACTION_MAP.get(args.action)
    if fn is None:
        raise RuntimeError(f"Action not yet migrated: {args.action}")
    fn()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        LOG.error(str(e))
        sys.exit(1)
