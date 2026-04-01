#!/usr/bin/env python3
"""
upgrade_commit.py (Pythonized from upgrade_commit.sh)

Performs the upgrade commit operation for the oGRAC cluster.
"""
import os
import sys
import subprocess
import shutil
import time
import glob as glob_mod

CUR_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, CUR_PATH)

from config import get_config, get_value
from docker_common.docker_log import log_and_echo_info, log_and_echo_error

_cfg = get_config()
_paths = _cfg.paths

PKG_PATH = os.path.abspath(os.path.join(CUR_PATH, "../.."))
VERSION_FILE = "versions.yml"
CLUSTER_COMMIT_STATUS = ("prepared", "commit")
WAIT_TIME = 10


def exec_cmd(cmd, timeout=300):
    proc = subprocess.Popen(
        ["bash"], shell=False,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    proc.stdin.write(cmd.encode())
    proc.stdin.write(os.linesep.encode())
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        return -1, "", "timeout"
    return proc.returncode, stdout.decode().strip(), stderr.decode().strip()


def read_file_content(filepath):
    if not os.path.isfile(filepath):
        return ""
    with open(filepath, "r") as f:
        return f.read().strip()


def write_file_content(filepath, content):
    with open(filepath, "w") as f:
        f.write(content)


def import_dbstor_helpers():
    """Import dbstor_tool_opt_common functions."""
    from dbstor_tool_opt_common import (
        update_local_status_file_path_by_dbstor,
        update_remote_status_file_path_by_dbstor,
        delete_fs_upgrade_file_or_path_by_dbstor,
        update_version_yml_by_dbstor,
    )
    return {
        "update_local": update_local_status_file_path_by_dbstor,
        "update_remote": update_remote_status_file_path_by_dbstor,
        "delete_fs": delete_fs_upgrade_file_or_path_by_dbstor,
        "update_version": update_version_yml_by_dbstor,
    }


cluster_and_node_status_path = ""
cluster_status_flag = ""
cluster_commit_flag = ""
modify_sys_table_success_flag = ""
source_version = ""
upgrade_path = ""


def init_cluster_status_flag():
    global cluster_and_node_status_path, cluster_status_flag
    global cluster_commit_flag, modify_sys_table_success_flag
    global source_version, upgrade_path

    storage_metadata_fs = get_value("storage_metadata_fs")
    metadata_path = _paths.metadata_fs_path(storage_metadata_fs)

    helpers = import_dbstor_helpers()
    helpers["update_local"]()

    upgrade_path = os.path.join(metadata_path, "upgrade")
    cluster_and_node_status_path = os.path.join(upgrade_path, "cluster_and_node_status")
    cluster_status_flag = os.path.join(cluster_and_node_status_path, "cluster_status.txt")
    modify_sys_table_success_flag = os.path.join(upgrade_path, "updatesys.success")

    version_file = os.path.join(metadata_path, VERSION_FILE)
    source_version = ""
    if os.path.isfile(version_file):
        with open(version_file, "r") as f:
            for line in f:
                if "Version:" in line:
                    raw = line.split(":")[-1].strip()
                    import re
                    source_version = re.sub(r'^[a-zA-Z]*0*', '', raw).strip()
                    break

    cluster_commit_flag = os.path.join(upgrade_path, f"ograc_upgrade_commit_{source_version}.success")
    log_and_echo_info("init cluster status flag success")


def check_upgrade_commit_flag():
    for i in range(3):
        if os.path.isfile(cluster_commit_flag):
            log_and_echo_info(f"flag file '{cluster_commit_flag}' has been detected")
            return True
        log_and_echo_info(f"flag file '{cluster_commit_flag}' is not detected, remaining attempts: {2 - i}")
        time.sleep(WAIT_TIME)
    return False


def node_status_check():
    """Return 3 if all nodes upgraded successfully, else 0/exit(1)."""
    cms_ip = get_value("cms_ip")
    upgrade_mode = get_value("upgrade_mode")
    node_count = cms_ip.count(";") + 1

    if not os.path.isdir(cluster_and_node_status_path):
        return 0

    status_array = []
    for fname in sorted(os.listdir(cluster_and_node_status_path)):
        import re
        if re.match(r'^node\d+_status\.txt$', fname):
            fpath = os.path.join(cluster_and_node_status_path, fname)
            status_array.append(read_file_content(fpath))

    if len(status_array) != node_count:
        log_and_echo_info(f"currently only {len(status_array)} nodes have performed the {upgrade_mode} upgrade, totals:{node_count}.")
        return 0

    unique = list(set(status_array))
    if len(unique) != 1:
        log_and_echo_info(f"existing nodes have not been upgraded successfully, details: {status_array}")
        return 0

    if unique[0] != f"{upgrade_mode}_success":
        log_and_echo_error(f"none of the {node_count} nodes were upgraded successfully")
        sys.exit(1)

    log_and_echo_info(f"all {node_count} nodes were upgraded successfully, pass check cluster upgrade status")
    return 3


def cluster_status_check():
    log_and_echo_info("begin to check cluster status")

    if not cluster_status_flag or not os.path.isfile(cluster_status_flag):
        log_and_echo_error(f"cluster status file '{cluster_and_node_status_path}' does not exist.")
        sys.exit(1)

    cluster_status = read_file_content(cluster_status_flag)
    ns = node_status_check()

    if not cluster_status:
        log_and_echo_error(f"no cluster status information in '{cluster_and_node_status_path}'")
        sys.exit(1)
    elif cluster_status not in CLUSTER_COMMIT_STATUS and ns != 3:
        log_and_echo_error(f"the cluster status must be one of '{CLUSTER_COMMIT_STATUS}', instead of {cluster_status}")
        sys.exit(1)

    log_and_echo_info(f"check cluster status success, current cluster status: {cluster_status}")


def modify_cluster_status(status_file, new_status):
    if status_file and not os.path.isfile(status_file):
        log_and_echo_info("rollup upgrade status does not exist.")
        sys.exit(1)

    old_status = read_file_content(status_file)
    if old_status == new_status:
        log_and_echo_info(f"the old status is consistent with the new status, both are {new_status}")
        return

    write_file_content(status_file, new_status)
    log_and_echo_info(f"change upgrade status from '{old_status}' to '{new_status}' success.")


def raise_version_num():
    ograc_user = get_value("deploy_user")
    log_and_echo_info("begin to call cms tool to raise the version num")

    version_path = os.path.join(PKG_PATH, VERSION_FILE)
    target_numbers = ""
    if os.path.isfile(version_path):
        with open(version_path, "r") as f:
            for line in f:
                if "Version:" in line:
                    raw = line.split()[-1]
                    import re
                    target_numbers = re.sub(r'\.[A-Z].*', '', raw)
                    break

    format_target = target_numbers.replace(".", " ") + " 0"

    for i in range(1, 11):
        code, _, _ = exec_cmd(f'su -s /bin/bash - "{ograc_user}" -c "cms upgrade -version {format_target}"')
        if code != 0:
            log_and_echo_error(f"calling cms tool to raise the version num failed, current attempt:{i}/10")
            time.sleep(10)
        else:
            break
    else:
        sys.exit(1)

    log_and_echo_info("calling cms tool to raise the version num success")


def upgrade_commit():
    node_id = get_value("node_id")
    if str(node_id) != "0":
        log_and_echo_error("Upgrade commit only allows operations at node 0. Please check.")
        sys.exit(1)

    cluster_status_check()
    modify_cluster_status(cluster_status_flag, "commit")
    raise_version_num()
    modify_cluster_status(cluster_status_flag, "normal")

    with open(cluster_commit_flag, "w"):
        pass
    os.chmod(cluster_commit_flag, 0o600)

    time.sleep(WAIT_TIME)
    if not check_upgrade_commit_flag():
        log_and_echo_error("Touch rollup upgrade commit tag file failed.")
        sys.exit(1)

    helpers = import_dbstor_helpers()
    helpers["update_remote"](cluster_status_flag)


def clear_upgrade_residual_data():
    log_and_echo_info("begin to clear residual data")

    target_version_path = os.path.join(PKG_PATH, VERSION_FILE)
    target_version = ""
    if os.path.isfile(target_version_path):
        with open(target_version_path, "r") as f:
            for line in f:
                if "Version:" in line:
                    import re
                    raw = line.split(":")[-1].strip()
                    target_version = re.sub(r'^[a-zA-Z]*0*', '', raw).strip()
                    break

    updatesys_success = os.path.join(upgrade_path, "updatesys.success")
    updatesys_failed = os.path.join(upgrade_path, "updatesys.failed")

    if os.path.isdir(cluster_and_node_status_path):
        shutil.rmtree(cluster_and_node_status_path, ignore_errors=True)
    if os.path.isfile(updatesys_success):
        os.remove(updatesys_success)
    if os.path.isfile(updatesys_failed):
        os.remove(updatesys_failed)

    for f in glob_mod.glob(os.path.join(upgrade_path, f"upgrade_node*.{target_version}")):
        os.remove(f)

    helpers = import_dbstor_helpers()
    helpers["delete_fs"]("cluster_and_node_status")
    helpers["delete_fs"]("updatesys.*")
    helpers["delete_fs"](f"upgrade_node.*.{target_version}")

    log_and_echo_info("clear residual data success")


def set_version_file():
    version_src = os.path.join(PKG_PATH, VERSION_FILE)
    if not os.path.isfile(version_src):
        log_and_echo_error(f"{VERSION_FILE} is not exist!")
        sys.exit(1)

    storage_metadata_fs = get_value("storage_metadata_fs")
    metadata_path = _paths.metadata_fs_path(storage_metadata_fs)

    shutil.copy2(version_src, os.path.join(metadata_path, VERSION_FILE))

    helpers = import_dbstor_helpers()
    helpers["update_version"]()

    initdb_src = _paths.initdb_sql
    if os.path.isfile(initdb_src):
        shutil.copy2(initdb_src, os.path.join(metadata_path, "initdb.sql"))


def main():
    log_and_echo_info("begin to perform the upgrade commit operation")
    init_cluster_status_flag()
    if check_upgrade_commit_flag():
        log_and_echo_info("perform the upgrade commit operation has been successful")
        return
    upgrade_commit()
    log_and_echo_info("perform the upgrade commit operation success")
    clear_upgrade_residual_data()
    set_version_file()


if __name__ == "__main__":
    main()
