#!/usr/bin/env python3
"""
mount.py (Pythonized from mount.sh)

Mounts NFS file systems for the oGRAC container.
"""
import os
import sys
import subprocess

CUR_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, CUR_PATH)

from config import get_config, get_value
from docker_common.docker_log import log_and_echo_info, log_and_echo_error

_cfg = get_config()
_paths = _cfg.paths

NFS_TIMEO = 50


def exec_cmd(cmd, timeout=300):
    """Run a shell command."""
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


def check_mount_nfs(result, mount_nfs_ok):
    """Check NFS mount result, update overall flag."""
    if result != 0:
        mount_nfs_ok[0] = False
        log_and_echo_error(f"NFS mount failed with exit code {result}")


def check_port(nfs_port):
    """Find an available NFS callback port in range nfs_port..nfs_port+9."""
    for i in range(10):
        port = nfs_port + i
        code, out, _ = exec_cmd(f"netstat -tunpl 2>/dev/null | grep {port}")
        if code != 0 or not out.strip():
            log_and_echo_info(f"Port[{port}] is available")
            return port
        occupied = out.strip().split()
        if len(occupied) >= 7 and occupied[6] == "-":
            log_and_echo_info(f"Port[{port}] is available")
            return port
        log_and_echo_error(f"Port {port} has been temporarily used by a non-nfs process")

    log_and_echo_error("Port 36729~36738 has been temporarily used, please set NFS_PORT environment variable")
    sys.exit(1)


def copy_deploy_param(node_id, config_path, storage_metadata_fs, ograc_user, ograc_group):
    """Copy deploy_param.json to metadata FS if node_id == 0."""
    if str(node_id) == "0":
        metadata = _paths.metadata_fs_path(storage_metadata_fs)
        src = os.path.join(config_path, "deploy_param.json")
        dst = os.path.join(metadata, "deploy_param.json")
        exec_cmd(f"cp -rf {src} {dst} && chmod 600 {dst} && chown {ograc_user}:{ograc_group} {dst}")


def mount_fs():
    """Main mount logic."""
    mount_nfs_ok = [True]

    node_id = get_value("node_id")
    deploy_mode = get_value("deploy_mode")
    ograc_user = get_value("deploy_user")
    ograc_group = get_value("deploy_group")

    deploy_user = ograc_user
    storage_share_fs = get_value("storage_share_fs")
    storage_archive_fs = get_value("storage_archive_fs")
    storage_metadata_fs = get_value("storage_metadata_fs")

    config_path = os.path.join(CUR_PATH, "../../config")

    share_path = _paths.share_fs_path(storage_share_fs)
    metadata_path = _paths.metadata_fs_path(storage_metadata_fs)

    exec_cmd(f"mkdir -m 750 -p {share_path} && chown {ograc_user}:{ograc_group} {share_path}")

    if storage_archive_fs:
        archive_path = _paths.archive_fs_path(storage_archive_fs)
        exec_cmd(f"mkdir -m 750 -p {archive_path} && chown {ograc_user}:{ograc_group} {archive_path}")

    exec_cmd(f"mkdir -m 755 -p {metadata_path}")

    metadata_logic_ip = get_value("metadata_logic_ip")

    if deploy_mode != "file":
        kerberos_type = get_value("kerberos_key")
        mount_cmd = (f"mount -t nfs -o sec={kerberos_type},timeo={NFS_TIMEO},nosuid,nodev "
                     f"{metadata_logic_ip}:/{storage_metadata_fs} {metadata_path}")
    else:
        mount_cmd = (f"mount -t nfs -o timeo={NFS_TIMEO},nosuid,nodev "
                     f"{metadata_logic_ip}:/{storage_metadata_fs} {metadata_path}")

    metadata_result, _, _ = exec_cmd(mount_cmd)
    if metadata_result != 0:
        log_and_echo_error("mount metadata nfs failed")

    nfs_port_env = os.environ.get("NFS_PORT", "36729")
    nfs_port = int(nfs_port_env) if nfs_port_env.isdigit() else 36729
    nfs_port = check_port(nfs_port)
    exec_cmd(f"sysctl fs.nfs.nfs_callback_tcpport={nfs_port} > /dev/null 2>&1")

    if storage_archive_fs:
        archive_logic_ip = get_value("archive_logic_ip")
        archive_path = _paths.archive_fs_path(storage_archive_fs)
        if not archive_logic_ip:
            log_and_echo_info("please check archive_logic_ip")

        if deploy_mode != "file":
            mount_cmd = (f"mount -t nfs -o sec={kerberos_type},timeo={NFS_TIMEO},nosuid,nodev "
                         f"{archive_logic_ip}:/{storage_archive_fs} {archive_path}")
        else:
            mount_cmd = (f"mount -t nfs -o timeo={NFS_TIMEO},nosuid,nodev "
                         f"{archive_logic_ip}:/{storage_archive_fs} {archive_path}")

        archive_result, _, _ = exec_cmd(mount_cmd)
        if archive_result != 0:
            log_and_echo_error("mount archive nfs failed")
        check_mount_nfs(archive_result, mount_nfs_ok)

        deploy_group = get_value("deploy_group")
        exec_cmd(f"chmod 750 {archive_path} && chown -hR {ograc_user}:{deploy_group} {archive_path} > /dev/null 2>&1")

    check_mount_nfs(metadata_result, mount_nfs_ok)

    if deploy_mode == "file":
        share_logic_ip = get_value("share_logic_ip")
        storage_dbstor_fs = get_value("storage_dbstor_fs")
        storage_logic_ip = get_value("storage_logic_ip")

        mount_cmd = (f"mount -t nfs -o vers=4.0,timeo={NFS_TIMEO},nosuid,nodev "
                     f"{share_logic_ip}:/{storage_share_fs} {share_path}")
        share_result, _, _ = exec_cmd(mount_cmd)
        if share_result != 0:
            log_and_echo_error("mount share nfs failed")
        exec_cmd(f"chown -hR {ograc_user}:{ograc_group} {share_path} > /dev/null 2>&1")
        check_mount_nfs(share_result, mount_nfs_ok)

        storage_path = _paths.storage_fs_path(storage_dbstor_fs)
        exec_cmd(f"mkdir -m 750 -p {storage_path}")
        mount_cmd = (f"mount -t nfs -o vers=4.0,timeo={NFS_TIMEO},nosuid,nodev "
                     f"{storage_logic_ip}:/{storage_dbstor_fs} {storage_path}")
        dbstor_result, _, _ = exec_cmd(mount_cmd)
        if dbstor_result != 0:
            log_and_echo_error("mount dbstor nfs failed")
        exec_cmd(f"chown {ograc_user}:{ograc_user} {storage_path}")
        check_mount_nfs(dbstor_result, mount_nfs_ok)

        local_data = _paths.local_data
        exec_cmd(f"mkdir -m 750 -p {storage_path}/data && mkdir -m 750 -p {storage_path}/share_data")
        exec_cmd(f"rm -rf {local_data}/data && ln -s {storage_path}/data/ {local_data}/data")
        exec_cmd(f"chown -h {ograc_user}:{ograc_user} {local_data}/data")
        exec_cmd(f"chown -h {ograc_user}:{ograc_user} {storage_path}/data")
        exec_cmd(f"chown -h {ograc_user}:{ograc_user} {storage_path}/share_data")

    if not mount_nfs_ok[0]:
        log_and_echo_info("mount nfs failed")
        sys.exit(1)

    code, remote_info, _ = exec_cmd(f"ls -l {_paths.remote_data}")
    log_and_echo_info(f"{_paths.remote_data} detail is: {remote_info}")

    exec_cmd(f"chmod 750 {share_path}")
    exec_cmd(f"chmod 755 {metadata_path}")

    node_id = get_value("node_id")
    copy_deploy_param(node_id, config_path, storage_metadata_fs, ograc_user, ograc_group)

    ograc_common_group = _cfg.ograc_common_group
    if not os.path.isfile(os.path.join(metadata_path, "versions.yml")) and str(node_id) == "0":
        for nid in ["0", "1"]:
            node_dir = os.path.join(metadata_path, f"node{nid}")
            if os.path.isdir(node_dir):
                exec_cmd(f"rm -rf {node_dir}")
        exec_cmd(f"mkdir -m 770 -p {os.path.join(metadata_path, 'node0')} && "
                 f"chown {deploy_user}:{ograc_common_group} {os.path.join(metadata_path, 'node0')}")
        exec_cmd(f"mkdir -m 770 -p {os.path.join(metadata_path, 'node1')} && "
                 f"chown {deploy_user}:{ograc_common_group} {os.path.join(metadata_path, 'node1')}")
        gcc_file = _paths.gcc_file_path(storage_share_fs)
        if os.path.isfile(gcc_file):
            log_and_echo_error("gcc file already exists, please check if any cluster is running.")
            sys.exit(1)


if __name__ == "__main__":
    mount_fs()
