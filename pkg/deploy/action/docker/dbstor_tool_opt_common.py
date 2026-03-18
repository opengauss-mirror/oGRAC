#!/usr/bin/env python3
"""
dbstor_tool_opt_common.py (Pythonized from dbstor_tool_opt_common.sh)

Provides helper functions for dbstor filesystem operations used by
container_upgrade.py and upgrade_commit.py.
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

PKG_PATH = os.path.abspath(os.path.join(CUR_PATH, "../.."))
VERSION_FILE = "versions.yml"

deploy_mode = get_value("deploy_mode")
storage_share_fs = get_value("storage_share_fs")
storage_metadata_fs = get_value("storage_metadata_fs")
ograc_in_container = get_value("ograc_in_container")
node_id = get_value("node_id")
ograc_user = get_value("deploy_user")
ograc_group = get_value("deploy_group")
lock_file_prefix = "upgrade_lock_"

METADATA_FS_PATH = _paths.metadata_fs_path(storage_metadata_fs) if storage_metadata_fs else ""


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



def get_dbs_version():
    """Return 1 for old dbstor API, 2 for new."""
    code, out, _ = exec_cmd(
        f'su -s /bin/bash - "{ograc_user}" -c "dbstor --query-file --fs-name={storage_share_fs} --file-dir=/"'
    )
    if code != 0:
        log_and_echo_info("Failed to execute dbstor --query-file, dbstor version is old.")
        return 1
    return 2



def query_filesystem(dbs_version, fs, directory="/"):
    """Query files in a filesystem directory."""
    if dbs_version == 1:
        cmd = f'su -s /bin/bash - "{ograc_user}" -c "dbstor --query-file --fs-name={fs} --file-path={directory}"'
    else:
        cmd = f'su -s /bin/bash - "{ograc_user}" -c "dbstor --query-file --fs-name={fs} --file-dir={directory}"'
    code, out, _ = exec_cmd(cmd)
    return out


def copy_file_from_filesystem(dbs_version, fs, source_dir, target_dir, file_name=""):
    """Export/copy a file from filesystem to local."""
    if dbs_version == 1:
        if not file_name:
            cmd = (f'su -s /bin/bash - "{ograc_user}" -c "dbstor --copy-file --fs-name={fs} '
                   f'--source-dir={source_dir} --target-dir={target_dir}"')
        else:
            cmd = (f'su -s /bin/bash - "{ograc_user}" -c "dbstor --copy-file --fs-name={fs} '
                   f'--source-dir={source_dir} --target-dir={target_dir} --file-name={file_name}"')
    else:
        if not file_name:
            cmd = (f'su -s /bin/bash - "{ograc_user}" -c "dbstor --copy-file --export --fs-name={fs} '
                   f'--source-dir={source_dir} --target-dir={target_dir} --overwrite"')
        else:
            cmd = (f'su -s /bin/bash - "{ograc_user}" -c "dbstor --copy-file --export --fs-name={fs} '
                   f'--source-dir={source_dir} --target-dir={target_dir} --file-name={file_name} --overwrite"')

    code, out, _ = exec_cmd(cmd)
    if code != 0:
        log_and_echo_error(
            f"Failed to execute dbstor --copy-file --export, fs[{fs}], "
            f"source_dir[{source_dir}], target_dir[{target_dir}], file_name[{file_name}], dbs_version[{dbs_version}]."
        )
    return code


def copy_file_to_filesystem(dbs_version, fs, source_dir, target_dir, file_name=""):
    """Import/copy a file from local to filesystem."""
    if dbs_version == 1:
        cmd = (f'su -s /bin/bash - "{ograc_user}" -c "dbstor --create-file --fs-name={fs} '
               f'--file-name=/{target_dir}/{file_name} --source-dir={source_dir}/{file_name}"')
    else:
        if not file_name:
            cmd = (f'su -s /bin/bash - "{ograc_user}" -c "dbstor --copy-file --import --fs-name={fs} '
                   f'--source-dir={source_dir} --target-dir={target_dir} --file-name={file_name} --overwrite"')
        else:
            cmd = (f'su -s /bin/bash - "{ograc_user}" -c "dbstor --copy-file --import --fs-name={fs} '
                   f'--source-dir={source_dir} --target-dir={target_dir} --file-name={file_name} --overwrite"')

    code, out, _ = exec_cmd(cmd)
    if code != 0:
        log_and_echo_error(
            f"Failed to execute dbstor --copy-file --import, fs[{fs}], "
            f"source_dir[{source_dir}], target_dir[{target_dir}], file_name[{file_name}], dbs_version[{dbs_version}]."
        )
    return code


def create_file_in_filesystem(dbs_version, fs, file_dir, file_name=""):
    """Create a file in the filesystem."""
    if dbs_version == 1:
        cmd = (f'su -s /bin/bash - "{ograc_user}" -c "dbstor --create-file --fs-name={fs} '
               f'--file-name={file_dir}/{file_name}"')
    else:
        if not file_name:
            cmd = (f'su -s /bin/bash - "{ograc_user}" -c "dbstor --create-file --fs-name={fs} '
                   f'--file-dir={file_dir}"')
        else:
            cmd = (f'su -s /bin/bash - "{ograc_user}" -c "dbstor --create-file --fs-name={fs} '
                   f'--file-dir={file_dir} --file-name={file_name}"')

    code, out, _ = exec_cmd(cmd)
    if code != 0:
        log_and_echo_error(
            f"Failed to execute dbstor --create-file, fs[{fs}], "
            f"file_dir[{file_dir}], file_name[{file_name}], dbs_version[{dbs_version}]."
        )
    return code



def update_local_status_file_path_by_dbstor():
    """Copy upgrade status files from filesystem to local."""
    if deploy_mode == "dss":
        exec_cmd(f'mkdir -p "{METADATA_FS_PATH}/upgrade/cluster_and_node_status"')
        exec_cmd(f'chown "{ograc_user}":"{ograc_group}" "{METADATA_FS_PATH}/upgrade"')
        exec_cmd(f'chown "{ograc_user}":"{ograc_group}" "{METADATA_FS_PATH}/upgrade/cluster_and_node_status"')
        return

    if deploy_mode != "dbstor":
        return

    exec_cmd(f'chown "{ograc_user}":"{ograc_group}" {METADATA_FS_PATH}')
    dbs_vs = get_dbs_version()

    if ograc_in_container != "0":
        out = query_filesystem(dbs_vs, storage_share_fs)
        if "versions.yml" not in out:
            return
        versions_local = os.path.join(METADATA_FS_PATH, "versions.yml")
        if os.path.isfile(versions_local):
            os.remove(versions_local)
        code = copy_file_from_filesystem(dbs_vs, storage_share_fs, "/", METADATA_FS_PATH, VERSION_FILE)
        if code != 0:
            log_and_echo_error("Copy versions.yml from fs to local failed.")
            return

    out = query_filesystem(dbs_vs, storage_share_fs)
    import re
    if not re.search(r'upgrade$', out, re.MULTILINE):
        return

    upgrade_local = os.path.join(METADATA_FS_PATH, "upgrade")
    if os.path.isdir(upgrade_local):
        import shutil
        shutil.rmtree(upgrade_local, ignore_errors=True)

    os.makedirs(upgrade_local, mode=0o755, exist_ok=True)
    exec_cmd(f'chown "{ograc_user}":"{ograc_group}" "{upgrade_local}"')
    code = copy_file_from_filesystem(dbs_vs, storage_share_fs, "/upgrade", upgrade_local)
    if code != 0:
        log_and_echo_error("Copy upgrade path [upgrade] from fs to local failed.")
        return

    out2 = query_filesystem(dbs_vs, storage_share_fs, "/upgrade")
    if "cluster_and_node_status" not in out2:
        return

    cns_local = os.path.join(upgrade_local, "cluster_and_node_status")
    os.makedirs(cns_local, mode=0o755, exist_ok=True)
    exec_cmd(f'chown "{ograc_user}":"{ograc_group}" "{cns_local}"')
    code = copy_file_from_filesystem(dbs_vs, storage_share_fs, "/upgrade/cluster_and_node_status/", f"{cns_local}/")
    if code != 0:
        log_and_echo_error("Copy upgrade path [cluster_and_node_status] from fs to local failed.")


def update_remote_status_file_path_by_dbstor(cluster_or_node_status_file_path):
    """Copy status file from local to filesystem."""
    if deploy_mode == "dss":
        exec_cmd(f'chown -hR "{ograc_user}":"{ograc_group}" {METADATA_FS_PATH}/upgrade')
        dss_script = os.path.join(CUR_PATH, "dss/common/dss_upgrade_remote_status_file.py")
        code, _, _ = exec_cmd(
            f'su -s /bin/bash - "{ograc_user}" -c "python3 -B {dss_script} {cluster_or_node_status_file_path}"'
        )
        if code != 0:
            log_and_echo_error("file to remote failed.")
            sys.exit(1)
        return

    if deploy_mode != "dbstor":
        return

    dbs_vs = get_dbs_version()
    exec_cmd(f'chown -hR "{ograc_user}":"{ograc_group}" {METADATA_FS_PATH}/upgrade')

    upgrade_base = os.path.join(METADATA_FS_PATH, "upgrade")

    if os.path.isdir(cluster_or_node_status_file_path):
        relative_path = os.path.relpath(cluster_or_node_status_file_path, upgrade_base)
        if relative_path == ".":
            relative_path = ""
        local_path = os.path.join(upgrade_base, relative_path)
        exec_cmd(f'chmod 755 "{local_path}"')
        copy_file_to_filesystem(dbs_vs, storage_share_fs,
                                f"{upgrade_base}/{relative_path}", f"/upgrade/{relative_path}")
    else:
        file_name = os.path.basename(cluster_or_node_status_file_path)
        dir_path = os.path.dirname(cluster_or_node_status_file_path)
        relative_path = os.path.relpath(dir_path, upgrade_base)
        if relative_path == ".":
            relative_path = ""
        local_dir = os.path.join(upgrade_base, relative_path)
        if os.path.isdir(local_dir):
            exec_cmd(f'chmod 755 "{local_dir}"')
        local_file = os.path.join(upgrade_base, relative_path)
        if os.path.isfile(local_file):
            exec_cmd(f'chmod 600 "{local_file}"')
        copy_file_to_filesystem(dbs_vs, storage_share_fs,
                                f"{upgrade_base}/{relative_path}",
                                f"/upgrade/{relative_path}", file_name)

    log_and_echo_info("update remote status file completed.")


def delete_fs_upgrade_file_or_path_by_dbstor(file_name):
    """Delete matching files from upgrade directory in filesystem."""
    if deploy_mode == "dss":
        dss_script = os.path.join(CUR_PATH, "dss/common/dss_upgrade_delete.py")
        code, _, _ = exec_cmd(
            f'su -s /bin/bash - "{ograc_user}" -c "python3 -B {dss_script} {file_name}"'
        )
        if code != 0:
            log_and_echo_error("file to delete failed.")
            sys.exit(1)
        return

    if deploy_mode != "dbstor":
        return

    log_and_echo_info(f"Start to delete {file_name} in upgrade path")
    dbs_vs = get_dbs_version()
    out = query_filesystem(dbs_vs, storage_share_fs, "/upgrade")

    import re
    matches = [line.strip() for line in out.splitlines() if re.search(file_name, line)]

    if matches:
        for _file in matches:
            exec_cmd(
                f'su -s /bin/bash - "{ograc_user}" -c "dbstor --delete-file '
                f'--fs-name={storage_share_fs} --file-name=/upgrade/{_file}"'
            )


def update_version_yml_by_dbstor():
    """Copy versions.yml to filesystem."""
    if deploy_mode == "dss":
        version_file = os.path.join(PKG_PATH, VERSION_FILE)
        exec_cmd(f'chown "{ograc_user}":"{ograc_group}" "{version_file}"')
        dss_script = os.path.join(CUR_PATH, "dss/common/dss_upgrade_yaml.py")
        code, _, _ = exec_cmd(
            f'su -s /bin/bash - "{ograc_user}" -c "python3 -B {dss_script} {version_file}"'
        )
        if code != 0:
            log_and_echo_error("file to yml failed.")
            sys.exit(1)
        return

    if deploy_mode != "dbstor":
        return

    version_file = os.path.join(PKG_PATH, VERSION_FILE)
    exec_cmd(f'chown "{ograc_user}":"{ograc_group}" "{version_file}"')
    dbs_vs = get_dbs_version()
    code = copy_file_to_filesystem(dbs_vs, storage_share_fs, PKG_PATH, "/", VERSION_FILE)
    if code != 0:
        log_and_echo_error("Execute dbstor tool command: --copy-file failed.")
        sys.exit(1)


def upgrade_lock_by_dbstor():
    """Acquire upgrade lock in filesystem."""
    node_lock_file = f"{lock_file_prefix}{node_id}"

    if deploy_mode == "dss":
        exec_cmd(f"touch {METADATA_FS_PATH}/upgrade/{node_lock_file}")
        dss_script = os.path.join(CUR_PATH, "dss/common/dss_upgrade_lock.py")
        code, _, _ = exec_cmd(
            f'su -s /bin/bash - "{ograc_user}" -c "python3 -B {dss_script} {node_lock_file}"'
        )
        if code != 0:
            log_and_echo_error("file to lock failed.")
            sys.exit(1)
        return

    if deploy_mode != "dbstor":
        return

    dbs_vs = get_dbs_version()
    out = query_filesystem(dbs_vs, storage_share_fs, "/upgrade")
    import re
    upgrade_nodes = len(re.findall(lock_file_prefix, out))
    node_matches = len(re.findall(node_lock_file, out))

    if upgrade_nodes > 1:
        log_and_echo_error(f"Exist other upgrade node, details:{upgrade_nodes}")
        sys.exit(1)
    if upgrade_nodes == 1 and node_matches == 0:
        log_and_echo_error(f"Exist upgrade node, details:{upgrade_nodes}")
        sys.exit(1)
    if node_matches == 1:
        return

    code = create_file_in_filesystem(dbs_vs, storage_share_fs, "/upgrade", node_lock_file)
    if code != 0:
        log_and_echo_error("upgrade lock failed")
        sys.exit(1)


def upgrade_unlock_by_dbstor():
    """Release upgrade lock in filesystem."""
    node_lock_file = f"{lock_file_prefix}{node_id}"

    if deploy_mode == "dss":
        dss_script = os.path.join(CUR_PATH, "dss/common/dss_upgrade_unlock.py")
        code, _, _ = exec_cmd(
            f'su -s /bin/bash - "{ograc_user}" -c "python3 -B {dss_script} {node_lock_file}"'
        )
        if code != 0:
            log_and_echo_error("file to remote failed.")
            sys.exit(1)
        return

    if deploy_mode != "dbstor":
        return

    dbs_vs = get_dbs_version()
    out = query_filesystem(dbs_vs, storage_share_fs, "upgrade")

    if node_lock_file not in out:
        return

    code, _, _ = exec_cmd(
        f'su -s /bin/bash - "{ograc_user}" -c "dbstor --delete-file --fs-name={storage_share_fs} '
        f'--file-name=/upgrade/{node_lock_file}"'
    )
    if code != 0:
        log_and_echo_error("Execute clear lock file failed.")
        sys.exit(1)
