#!/usr/bin/env python3
"""
log_backup.py (Pythonized from log_backup.sh)

Backs up container logs into /home/mfdb_core/<cluster>_<id>/<timestamp>-node<nid>/
"""
import os
import sys
import shutil
from datetime import datetime
from pathlib import Path

CUR_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, CUR_PATH)

from config import get_config
from docker_common.docker_log import log_and_echo_info, log_and_echo_error

_cfg = get_config()
_paths = _cfg.paths

MAX_LOGS = 20


def delete_log_if_too_much(dir_path):
    """Delete the oldest date-stamped subdirectory if count > MAX_LOGS."""
    if not os.path.isdir(dir_path):
        log_and_echo_error(f"invalid log dir_path: {dir_path}")
        sys.exit(1)

    dated_dirs = sorted([
        d for d in Path(dir_path).iterdir()
        if d.is_dir() and len(d.name) >= 19
    ], key=lambda d: d.name)

    if len(dated_dirs) > MAX_LOGS:
        oldest = dated_dirs[0]
        log_and_echo_info(f"logs more than {MAX_LOGS}, begin to delete oldest log")
        shutil.rmtree(str(oldest), ignore_errors=True)
        log_and_echo_info(f"found oldest log: {oldest}, remove complete")


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


def check_path_and_copy(src_path, dst_path):
    """Copy src to dst if src exists."""
    if os.path.exists(src_path):
        if os.path.isdir(src_path):
            dst = os.path.join(dst_path, os.path.basename(src_path))
            _copytree_compat(src_path, dst)
        else:
            shutil.copy2(src_path, dst_path)


def main():
    if len(sys.argv) not in (5, 6):
        log_and_echo_error("Usage: Please input 4 or 5 params: cluster_name cluster_id node_id deploy_user [storage_metadata_fs]")
        sys.exit(1)

    cluster_name = sys.argv[1]
    cluster_id = sys.argv[2]
    node_id = sys.argv[3]
    deploy_user = sys.argv[4]
    storage_metadata_fs = sys.argv[5] if len(sys.argv) > 5 else ""

    log_and_echo_info("Backup log begin.")
    date_str = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    base_dir = f"/home/mfdb_core/{cluster_name}_{cluster_id}"
    backup_dir = os.path.join(base_dir, f"{date_str}-node{node_id}")
    os.makedirs(backup_dir, exist_ok=True)
    delete_log_if_too_much(base_dir)

    for sub in ["ograc/opt", "ograc/mnt", "cms", "dbstor/opt", "dbstor/mnt",
                "dbstor/ftds", "dbstor/install", "core_symbol"]:
        os.makedirs(os.path.join(backup_dir, sub), exist_ok=True)

    local_data = _paths.local_data
    ograc_home = _paths.ograc_home

    check_path_and_copy(os.path.join(local_data, "log"), os.path.join(backup_dir, "ograc/mnt"))
    check_path_and_copy(os.path.join(local_data, "cfg"), os.path.join(backup_dir, "ograc/mnt"))
    check_path_and_copy(os.path.join(ograc_home, "log", "ograc"), os.path.join(backup_dir, "ograc/opt"))
    check_path_and_copy(os.path.join(ograc_home, "log", "deploy"), os.path.join(backup_dir, "ograc/opt"))
    check_path_and_copy(_paths.ograc_exporter_dir, os.path.join(backup_dir, "ograc/opt"))
    check_path_and_copy(_paths.common_config_dir, os.path.join(backup_dir, "ograc/opt"))
    check_path_and_copy(os.path.join(ograc_home, "log", "cms"), os.path.join(backup_dir, "cms"))
    check_path_and_copy(os.path.join(ograc_home, "log", "dbstor"), os.path.join(backup_dir, "dbstor/mnt"))
    check_path_and_copy(os.path.join(ograc_home, "cms", "dbstor", "data", "logs"), os.path.join(backup_dir, "dbstor/opt"))
    check_path_and_copy(os.path.join(ograc_home, "dbstor", "data", "logs"), os.path.join(backup_dir, "dbstor/install"))
    check_path_and_copy(os.path.join(local_data, "dbstor", "data", "ftds", "ftds", "data", "stat"),
                        os.path.join(backup_dir, "dbstor/ftds"))
    check_path_and_copy(_paths.ograc_server_bin, os.path.join(backup_dir, "core_symbol"))

    log_and_echo_info("Backup log complete.")


if __name__ == "__main__":
    main()
