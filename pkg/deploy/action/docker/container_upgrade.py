#!/usr/bin/env python3
"""
container_upgrade.py (Pythonized from container_upgrade.sh)

Handles container upgrade logic: version checking, rollback, white-list,
upgrade flag management, cluster/node status tracking, and system table modification.
"""
import os
import re
import sys
import subprocess
import shutil
import time

CUR_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, CUR_PATH)

from config import get_config, get_value
from docker_common.docker_log import log_and_echo_info, log_and_echo_error
from dbstor_tool_opt_common import (
    update_local_status_file_path_by_dbstor,
    update_remote_status_file_path_by_dbstor,
    delete_fs_upgrade_file_or_path_by_dbstor,
    update_version_yml_by_dbstor,
)

_cfg = get_config()
_paths = _cfg.paths

PKG_PATH = os.path.abspath(os.path.join(CUR_PATH, "../.."))
SCRIPT_NAME = "container_upgrade.py"
VERSION_FILE = "versions.yml"
START_STATUS_NAME = "start_status.json"
CLUSTER_COMMIT_STATUS = ("prepared", "commit")
CLUSTER_PREPARED = 3

storage_metadata_fs = get_value("storage_metadata_fs")
node_id = get_value("node_id")
cms_ip = get_value("cms_ip")
ograc_user = get_value("deploy_user")
ograc_group = get_value("deploy_group")
deploy_mode = get_value("deploy_mode")
upgrade_mode = get_value("upgrade_mode")

METADATA_FS_PATH = _paths.metadata_fs_path(storage_metadata_fs) if storage_metadata_fs else ""
upgrade_path = os.path.join(METADATA_FS_PATH, "upgrade") if METADATA_FS_PATH else ""
upgrade_lock_path = os.path.join(METADATA_FS_PATH, "upgrade.lock") if METADATA_FS_PATH else ""
cluster_and_node_status_path = os.path.join(upgrade_path, "cluster_and_node_status") if upgrade_path else ""
DORADO_CONF_PATH = _paths.dorado_conf_path()
SYS_PASS = "sysPass"

local_version = ""
remote_version = ""
cluster_status_flag = ""
local_node_status_flag = ""
local_node_status = ""
modify_systable = ""
upgrade_flag = ""
updatesys_flag = ""


def exec_cmd(cmd, timeout=600):
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


def read_file(filepath):
    if not os.path.isfile(filepath):
        return ""
    with open(filepath, "r") as f:
        return f.read().strip()


def write_file(filepath, content):
    with open(filepath, "w") as f:
        f.write(content)


def parse_version(version_file_path):
    """Extract normalized version from a versions.yml file."""
    if not os.path.isfile(version_file_path):
        return ""
    with open(version_file_path, "r") as f:
        for line in f:
            if "Version:" in line:
                raw = line.split(":")[-1].strip()
                return re.sub(r'^[a-zA-Z]*0*', '', raw).strip()
    return ""



def check_if_need_upgrade():
    """Return True if upgrade needed, False otherwise. Exit 1 if outdated."""
    global local_version, remote_version
    remote_versions_path = os.path.join(METADATA_FS_PATH, VERSION_FILE)
    if not os.path.isfile(remote_versions_path):
        log_and_echo_info(f"this is first to start node, no need to upgrade. [File:{SCRIPT_NAME}]")
        sys.exit(0)

    log_and_echo_info(f"check if the container needs to upgrade. [File:{SCRIPT_NAME}]")
    local_version = parse_version(os.path.join(PKG_PATH, VERSION_FILE))
    remote_version = parse_version(remote_versions_path)

    if local_version < remote_version:
        log_and_echo_error(
            f"The version is outdated. cluster version:{remote_version}, but this version:{local_version}. [File:{SCRIPT_NAME}]"
        )
        sys.exit(1)
    if local_version > remote_version:
        return True
    return False



def rollback_check_cluster_status():
    if not os.path.isdir(cluster_and_node_status_path):
        log_and_echo_info("the cluster status dir is not exist, no need to rollback.")
        return False

    cs_flag = os.path.join(cluster_and_node_status_path, "cluster_status.txt")
    if not os.path.isfile(cs_flag):
        log_and_echo_info("the cluster status file is not exist, no need to rollback.")
        return False

    cs = read_file(cs_flag)
    if cs == "commit":
        log_and_echo_info("the cluster status is commit, failed to rollback.")
        sys.exit(1)
    if cs == "normal":
        log_and_echo_info("the cluster status is normal, no need to rollback.")
        return False

    modify_cluster_or_node_status(cs_flag, "rollback", "cluster")
    return True


def rollback_check_local_node_status():
    log_and_echo_info("begin to check if the current node needs to rollback.")
    lns_flag = os.path.join(cluster_and_node_status_path, f"node{node_id}_status.txt")
    if not os.path.isfile(lns_flag):
        log_and_echo_info("the current node has not been upgraded, no need to rollback.")
        return False
    modify_cluster_or_node_status(lns_flag, "rollback", f"node{node_id}")
    log_and_echo_info("pass check if the current node needs roll back.")
    return True


def rollback_check():
    log_and_echo_info("begin to check if the container needs to rollback.")
    if not rollback_check_cluster_status():
        log_and_echo_info("the cluster status is not prepared, no need to rollback.")
        return False
    if not rollback_check_local_node_status():
        log_and_echo_info("the current node status is not prepared, no need to rollback.")
        return False
    return True


def cluster_rollback_status_check():
    log_and_echo_info("begin to check cluster rollback status")
    node_count = cms_ip.count(";") + 1

    status_array = []
    if os.path.isdir(cluster_and_node_status_path):
        for fname in sorted(os.listdir(cluster_and_node_status_path)):
            if re.match(r'^node\d+_status\.txt$', fname):
                status_array.append(read_file(os.path.join(cluster_and_node_status_path, fname)))

    unique = list(set(status_array))
    if len(unique) != 1:
        log_and_echo_info(f"existing nodes have not been rollback successfully, details: {status_array}")
        return
    if unique[0] != "rollback_success":
        log_and_echo_error(f"none of the {node_count} nodes were rollback successfully.")
        sys.exit(1)

    cs_flag = os.path.join(cluster_and_node_status_path, "cluster_status.txt")
    modify_cluster_or_node_status(cs_flag, "normal", "cluster")
    log_and_echo_info("all nodes have been rollback successfully.")


def clear_flag_after_rollback():
    import glob as glob_mod
    for f in glob_mod.glob(os.path.join(upgrade_path, f"upgrade_node{node_id}.*")):
        os.remove(f)
    if os.path.isdir(cluster_and_node_status_path):
        shutil.rmtree(cluster_and_node_status_path, ignore_errors=True)
    delete_fs_upgrade_file_or_path_by_dbstor(f"upgrade_node{node_id}.*")
    delete_fs_upgrade_file_or_path_by_dbstor("cluster_and_node_status")


def do_rollback():
    log_and_echo_info("begin to rollback.")
    lns_flag = os.path.join(cluster_and_node_status_path, f"node{node_id}_status.txt")
    local_ns = read_file(lns_flag)
    if local_ns != "rollback_success":
        start_ogracd_by_cms()
        modify_cluster_or_node_status(lns_flag, "rollback_success", f"node{node_id}")
    cluster_rollback_status_check()
    clear_flag_after_rollback()



def check_white_list():
    global modify_systable
    if upgrade_mode not in ("rollup", "offline"):
        return False, f"Invalid upgrade_mode '{upgrade_mode}'. It should be either 'rollup' or 'offline'."

    code, out, _ = exec_cmd(f"python3 {os.path.join(CUR_PATH, 'upgrade_version_check.py')}")
    parts = out.split()
    if not parts:
        return False, "upgrade_version_check returned empty"

    upgrade_stat = parts[0]
    if upgrade_stat == "True":
        upgrade_support_mode = parts[2] if len(parts) > 2 else ""
        if upgrade_support_mode == "offline" and upgrade_mode == "rollup":
            return False, "current version does not support 'rollup' mode"

        if upgrade_mode == "offline":
            if not os.path.isdir(cluster_and_node_status_path):
                code2, cms_ret_out, _ = exec_cmd(
                    f'su -s /bin/bash - {ograc_user} -c "cms stat" | awk \'{{print $3}}\' | grep "ONLINE" | wc -l'
                )
                cms_ret = int(cms_ret_out) if cms_ret_out.isdigit() else 0
                if cms_ret != 0:
                    update_local_status_file_path_by_dbstor()
                    if not os.path.isdir(cluster_and_node_status_path):
                        return False, f"Current upgrade mode is offline, but ONLINE count is {cms_ret}"

        modify_systable = parts[1] if len(parts) > 1 else ""
        return True, ""
    else:
        err_info = parts[1] if len(parts) > 1 else "unknown"
        return False, err_info



def check_upgrade_flag():
    if not os.path.isdir(upgrade_path):
        return
    for fname in os.listdir(upgrade_path):
        if fname.startswith("upgrade") and local_version not in fname and fname != "upgrade.lock":
            log_and_echo_error(f"The cluster is being upgraded to another version: {fname}, current target version: {local_version}")
            sys.exit(1)


def create_upgrade_flag():
    if not os.path.isdir(upgrade_path):
        os.makedirs(upgrade_path, mode=0o755, exist_ok=True)

    if not os.path.isfile(upgrade_flag):
        with open(upgrade_flag, "w"):
            pass
        os.chmod(upgrade_flag, 0o600)
        update_remote_status_file_path_by_dbstor(upgrade_flag)

    if not os.path.isfile(upgrade_lock_path):
        with open(upgrade_lock_path, "w"):
            pass
        os.chmod(upgrade_lock_path, 0o600)

    if modify_systable == "true":
        updatesys_success = os.path.join(upgrade_path, "updatesys.success")
        if os.path.isfile(updatesys_flag) or os.path.isfile(updatesys_success):
            log_and_echo_info("detected that the system tables file flag already exists.")
            return
        with open(updatesys_flag, "w"):
            pass
        os.chmod(updatesys_flag, 0o600)
        log_and_echo_info(f"detect need to update system tables, success to create updatesys_flag: '{updatesys_flag}'")


def upgrade_init_flag():
    global upgrade_flag, updatesys_flag
    upgrade_flag = os.path.join(upgrade_path, f"upgrade_node{node_id}.{local_version}")
    updatesys_flag = os.path.join(upgrade_path, "updatesys.true")

    check_upgrade_flag()
    create_upgrade_flag()


def upgrade_lock():
    """Acquire upgrade lock using flock."""
    exec_cmd(f"exec 506>\"{upgrade_lock_path}\" && flock -x --wait 600 506", timeout=660)



def init_cluster_or_node_status_flag():
    global cluster_status_flag, local_node_status_flag

    if not os.path.isdir(cluster_and_node_status_path):
        os.makedirs(cluster_and_node_status_path, mode=0o755, exist_ok=True)

    cluster_status_flag = os.path.join(cluster_and_node_status_path, "cluster_status.txt")
    local_node_status_flag = os.path.join(cluster_and_node_status_path, f"node{node_id}_status.txt")

    log_and_echo_info("init current cluster status and node status flag success.")

    if os.path.isfile(cluster_status_flag):
        cs = read_file(cluster_status_flag)
        if cs in CLUSTER_COMMIT_STATUS:
            log_and_echo_info(f"the current cluster status is already {cs}, no need to execute the upgrade.")
            sys.exit(0)

    commit_success_file = os.path.join(upgrade_path, f"ograc_upgrade_commit_{remote_version}")
    if os.path.isfile(commit_success_file):
        os.remove(commit_success_file)


def check_if_any_node_in_upgrade_status():
    if deploy_mode == "dbstor":
        return
    log_and_echo_info("begin to check if any nodes in upgrading state")

    if not os.path.isdir(cluster_and_node_status_path):
        return

    status_array = []
    for fname in sorted(os.listdir(cluster_and_node_status_path)):
        if re.match(r'^node\d+_status\.txt$', fname) and f"node{node_id}" not in fname:
            status_array.append(read_file(os.path.join(cluster_and_node_status_path, fname)))

    if not status_array:
        return

    unique = list(set(status_array))
    if len(unique) != 1:
        log_and_echo_error(f"currently existing nodes are in upgrading state, details: {status_array}")
        sys.exit(1)
    if unique[0] != f"{upgrade_mode}_success":
        log_and_echo_error(f"there are currently other nodes in upgrading or other upgrade mode. current mode: {upgrade_mode}, details: {unique[0]}")
        sys.exit(1)
    log_and_echo_info("check pass, currently no nodes are in upgrading state.")


def modify_cluster_or_node_status(status_file, new_status, label):
    old_status = ""

    if status_file and not os.path.isfile(status_file):
        log_and_echo_info(f"{upgrade_mode} upgrade status of '{label}' does not exist.")

    if os.path.isfile(status_file):
        old_status = read_file(status_file)
        if old_status == new_status:
            log_and_echo_info(f"the old status of {label} is consistent with the new status, both are {new_status}")
            return

    write_file(status_file, new_status)
    log_and_echo_info(f"change upgrade status of {label} from '{old_status}' to '{new_status}' success.")

    if deploy_mode == "dbstor":
        update_remote_status_file_path_by_dbstor(status_file)


def local_node_upgrade_status_check():
    global local_node_status
    log_and_echo_info("begin to check local node upgrade status")
    if os.path.isfile(local_node_status_flag):
        cur = read_file(local_node_status_flag)
        if cur == f"{upgrade_mode}_success":
            local_node_status = f"{upgrade_mode}_success"
            log_and_echo_info(f"node{node_id} has been upgraded successfully")
            return
        elif cur == upgrade_mode:
            log_and_echo_info(f"node_{node_id} is in {upgrade_mode} state")
            return

    modify_cluster_or_node_status(local_node_status_flag, upgrade_mode, f"node{node_id}")
    log_and_echo_info("pass check local node upgrade status")


def cluster_upgrade_status_check():
    log_and_echo_info("begin to check cluster upgrade status")
    node_count = cms_ip.count(";") + 1

    status_array = []
    if os.path.isdir(cluster_and_node_status_path):
        for fname in sorted(os.listdir(cluster_and_node_status_path)):
            if re.match(r'^node\d+_status\.txt$', fname):
                status_array.append(read_file(os.path.join(cluster_and_node_status_path, fname)))

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



def start_ogracd_by_cms():
    log_and_echo_info("begin to start cms")
    cms_appctl = os.path.join(CUR_PATH, "../cms/appctl.sh")
    code, _, _ = exec_cmd(f"sh {cms_appctl} start")
    if code != 0:
        log_and_echo_error("start cms when upgrade failed")
        sys.exit(1)

    log_and_echo_info("begin to start ogracd")
    for i in range(1, 11):
        code, _, _ = exec_cmd(f'su -s /bin/bash - "{ograc_user}" -c "cms res -start db -node {node_id}"')
        if code != 0:
            log_and_echo_error(f"start ogracd by cms failed, remaining Attempts: {i}/10")
            time.sleep(20)
        else:
            start_status = _paths.start_status_json
            exec_cmd(
                f'su -s /bin/bash - "{ograc_user}" -c '
                f'"sed -i \'s/\\"start_status\\": \\"default\\"/\\"start_status\\": \\"started\\"/\' {start_status}"'
            )
            log_and_echo_info("start ogracd by cms success")
            return

    log_and_echo_error("start ogracd by cms failed")
    sys.exit(1)



def modify_sys_tables():
    ms_flag = os.path.join(upgrade_path, "updatesys.true")
    ms_success = os.path.join(upgrade_path, "updatesys.success")
    ms_failed = os.path.join(upgrade_path, "updatesys.failed")
    systable_home = _paths.systable_home
    old_initdb_sql = os.path.join(METADATA_FS_PATH, "initdb.sql")
    new_initdb_sql = os.path.join(systable_home, "..", "initdb.sql")

    if not os.path.isfile(ms_flag) or os.path.isfile(ms_success):
        log_and_echo_info("detected that the system tables have been modified or does not need to be modified")
        return

    code, _, _ = exec_cmd(f'diff "{old_initdb_sql}" "{new_initdb_sql}" > /dev/null')
    if code == 0:
        log_and_echo_info("two init.sql files are the same, no need to modify sys tables.")
        return

    log_and_echo_info("modify sys tables start")
    sys_password_file = os.path.join(DORADO_CONF_PATH, SYS_PASS)
    sys_password = ""
    if os.path.isfile(sys_password_file):
        with open(sys_password_file, "r") as f:
            sys_password = f.read().strip()

    exec_cmd(f'chown "{ograc_user}":"{ograc_group}" "{old_initdb_sql}"')

    bin_path = os.path.join(systable_home, "../../../bin")
    upgrade_systable_py = os.path.join(CUR_PATH, "upgrade_systable.py")
    cmd = (
        f'echo -e "{sys_password}" | su -s /bin/bash - "{ograc_user}" -c '
        f'"sh {CUR_PATH}/../docker/upgrade_systable.sh 127.0.0.1 {bin_path} {old_initdb_sql} {new_initdb_sql} {systable_home}"'
    )
    code, _, _ = exec_cmd(cmd, timeout=1800)
    if code != 0:
        log_and_echo_error("modify sys tables failed")
        with open(ms_failed, "w"):
            pass
        os.chmod(ms_failed, 0o600)
        sys.exit(1)

    if os.path.isfile(ms_flag):
        os.remove(ms_flag)
    with open(ms_success, "w"):
        pass
    os.chmod(ms_success, 0o600)
    log_and_echo_info("modify sys tables success")



def container_upgrade_check():
    need_upgrade = check_if_need_upgrade()
    if not need_upgrade:
        if rollback_check():
            upgrade_lock()
            do_rollback()
            sys.exit(0)
        log_and_echo_info(f"now is the latest version, no need to upgrade. [File:{SCRIPT_NAME}]")
        sys.exit(0)

    ok, err_info = check_white_list()
    if not ok:
        log_and_echo_error(f"failed to white list check. err_info:{err_info} [File:{SCRIPT_NAME}]")
        sys.exit(1)

    log_and_echo_info(f"upgrade check succeeded. [File:{SCRIPT_NAME}]")


def container_upgrade():
    log_and_echo_info(f"Begin to upgrade. [File:{SCRIPT_NAME}]")
    upgrade_init_flag()
    upgrade_lock()
    init_cluster_or_node_status_flag()
    check_if_any_node_in_upgrade_status()
    modify_cluster_or_node_status(cluster_status_flag, upgrade_mode, "cluster")
    local_node_upgrade_status_check()

    if local_node_status != f"{upgrade_mode}_success":
        start_ogracd_by_cms()
        modify_sys_tables()
        modify_cluster_or_node_status(local_node_status_flag, f"{upgrade_mode}_success", f"node{node_id}")

    ret = cluster_upgrade_status_check()
    if ret == CLUSTER_PREPARED:
        modify_cluster_or_node_status(cluster_status_flag, "prepared", "cluster")

    log_and_echo_info(f"container upgrade success. [File:{SCRIPT_NAME}]")


def main():
    update_local_status_file_path_by_dbstor()
    container_upgrade_check()
    container_upgrade()


if __name__ == "__main__":
    main()
