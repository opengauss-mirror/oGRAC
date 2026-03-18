#!/usr/bin/env python3
"""
ograc_initer.py (Pythonized from ograc_initer.sh – 483 lines)

Main container initialization entry-point. Orchestrates:
  - network readiness, CPU limit check
  - KMC / certificate preparation
  - filesystem mount
  - init_start (pre-install, container init, NUMA binding, upgrade, DR, start)
  - log processing loop
"""
import json
import os
import re
import resource
import shutil
import subprocess
import sys
import time

CUR_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, CUR_PATH)

from config import get_config, get_value
from docker_common.docker_log import (
    log_and_echo_info, log_and_echo_error,
)

_cfg = get_config()
_paths = _cfg.paths

SCRIPT_PATH = os.path.join(CUR_PATH, "..")
PKG_PATH = os.path.abspath(os.path.join(CUR_PATH, "../.."))
CONFIG_PATH = os.path.join(PKG_PATH, "config")
OPT_CONFIG_PATH = _paths.config_dir
INIT_CONFIG_PATH = os.path.join(CONFIG_PATH, "container_conf", "init_conf")
KMC_CONFIG_PATH = os.path.join(CONFIG_PATH, "container_conf", "kmc_conf")
CERT_CONFIG_PATH = os.path.join(CONFIG_PATH, "container_conf", "cert_conf")
CERT_PASS = "certPass"
CONFIG_NAME = "deploy_param.json"
START_STATUS_NAME = "start_status.json"
VERSION_FILE = "versions.yml"
PRE_INSTALL_PY_PATH = os.path.join(CUR_PATH, "../pre_install.py")
WAIT_TIMES = 120

HEALTHY_FILE = _paths.healthy_file
READINESS_FILE = _paths.readiness_file
CMS_CONTAINER_FLAG = _paths.cms_container_flag
LOGICREP_HOME = _paths.logicrep_home
USER_FILE = _paths.user_file



def exec_cmd(cmd, timeout=600):
    """Run a bash command, return (code, stdout, stderr)."""
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


def touch(path):
    with open(path, "a"):
        pass



storage_share_fs = get_value("storage_share_fs")
storage_archive_fs = get_value("storage_archive_fs")
storage_metadata_fs = get_value("storage_metadata_fs")
node_id_str = str(get_value("node_id"))
node_id = int(node_id_str) if node_id_str.isdigit() else 0
cms_ip = get_value("cms_ip")
ograc_user = get_value("deploy_user")
ograc_group = get_value("deploy_group")
run_mode = get_value("M_RUNING_MODE")
deploy_user = ograc_user
deploy_group = ograc_group
mes_ssl_switch = get_value("mes_ssl_switch")
ograc_in_container = get_value("ograc_in_container")
cluster_name = get_value("cluster_name")
cluster_id = get_value("cluster_id")
deploy_mode = get_value("deploy_mode")

primary_keystore = _paths.primary_keystore
standby_keystore = _paths.standby_keystore

VERSION_PATH = _paths.metadata_fs_path(storage_metadata_fs) if storage_metadata_fs else ""
gcc_file = _paths.gcc_file_path(storage_share_fs) if storage_share_fs else ""

WAIT_TIMES_ACTUAL = WAIT_TIMES
if deploy_mode == "file":
    WAIT_TIMES_ACTUAL = 3600



def _split_domain():
    parts = cms_ip.split(";")
    if node_id == 0:
        return parts[0] if len(parts) > 0 else "", parts[1] if len(parts) > 1 else ""
    else:
        return parts[1] if len(parts) > 1 else "", parts[0] if len(parts) > 0 else ""


node_domain, remote_domain = _split_domain()


def wait_config_done(current_domain):
    """Wait until domain is ping-reachable."""
    log_and_echo_info(f"Begin to wait network done. cms_ip: {current_domain}")
    for attempt in range(1, WAIT_TIMES_ACTUAL + 1):
        code, _, _ = exec_cmd(f'ping "{current_domain}" -c 1 -w 1', timeout=10)
        if code == 0:
            return
        log_and_echo_info(f"wait cms_ip: {current_domain} ready, it has been ping {attempt} times.")
        time.sleep(5)
    log_and_echo_error("timeout for resolving cms domain name!")
    exit_with_log()



def check_cpu_limit():
    my_cpu_num = os.environ.get("MY_CPU_NUM", "")
    if my_cpu_num and my_cpu_num.isdigit():
        if int(my_cpu_num) < 8:
            log_and_echo_error(f"cpu limit cannot be less than 8, current cpu limit is {my_cpu_num}.")
            exit_with_log()


def check_container_context():
    check_cpu_limit()



def mount_fs():
    if deploy_mode == "dbstor":
        log_and_echo_info("deploy_mode = dbstor, no need to mount file system.")
        metadata = _paths.metadata_fs_path(storage_metadata_fs) if storage_metadata_fs else ""
        share = _paths.share_fs_path(storage_share_fs) if storage_share_fs else ""
        archive = _paths.archive_fs_path(storage_archive_fs) if storage_archive_fs else ""
        for d in [metadata, share, archive]:
            if d:
                exec_cmd(f"mkdir -m 755 -p {d}")
        if metadata:
            for nid in ["0", "1"]:
                nd = os.path.join(metadata, f"node{nid}")
                exec_cmd(f"mkdir -m 770 -p {nd}")
                exec_cmd(f"chown {deploy_user}:{ograc_group} {nd}")
        exec_cmd(f"chmod 755 {_paths.remote_data}")
        touch(_paths.dbstor_unify_flag)
        return

    log_and_echo_info("Begin to mount file system.")
    mount_py = os.path.join(CUR_PATH, "mount.py")
    code, _, _ = exec_cmd(f"python3 {mount_py}", timeout=600)
    if code != 0:
        log_and_echo_error("mount file system failed.")
        exit_with_log()
    log_and_echo_info("mount file system success.")



def check_version_file():
    """Return True if versions.yml exists (on fs or local)."""
    if deploy_mode == "dbstor":
        code, out, _ = exec_cmd(
            f'su -s /bin/bash - "{ograc_user}" -c \'dbstor --query-file --fs-name={storage_share_fs} --file-dir=/\' | grep versions.yml | wc -l'
        )
        return out.strip() == "1"
    else:
        return os.path.isfile(os.path.join(VERSION_PATH, VERSION_FILE))


def check_init_status():
    if check_version_file():
        log_and_echo_info("wait remote domain ready.")
        wait_config_done(remote_domain)
        log_and_echo_info("The cluster has been initialized, no need create database.")
        start_status = _paths.start_status_json
        exec_cmd(f'sed -i \'s/"db_create_status": "default"/"db_create_status": "done"/g\' {start_status}')
        exec_cmd(f'sed -i \'s/"ever_started": false/"ever_started": true/g\' {start_status}')
        if os.path.isfile(USER_FILE):
            os.remove(USER_FILE)

    attempt = 1
    while not check_version_file() and node_id != 0:
        log_and_echo_info("wait for node 0 pod startup...")
        if attempt >= WAIT_TIMES_ACTUAL:
            log_and_echo_error("timeout for wait node 0 startup!")
            exit_with_log()
        attempt += 1
        time.sleep(5)



def prepare_kmc_conf():
    common_config = _paths.common_config_dir
    exec_cmd(f"cp -arf {KMC_CONFIG_PATH}/standby_keystore.ks {common_config}/")
    exec_cmd(f"cp -arf {KMC_CONFIG_PATH}/primary_keystore.ks {common_config}/")
    exec_cmd(f"cp -arf {KMC_CONFIG_PATH}/standby_keystore.ks {common_config}/standby_keystore_bak.ks")
    exec_cmd(f"cp -arf {KMC_CONFIG_PATH}/primary_keystore.ks {common_config}/primary_keystore_bak.ks")
    exec_cmd(f"chown -R {ograc_user}:{ograc_group} {common_config}/*")


def clear_sem_id():
    signal_num = "0x20161227"
    code, out, _ = exec_cmd(f"lsipc -s -c | grep {signal_num} | grep -v grep | awk '{{print $2}}'")
    sem_id = out.strip()
    if sem_id:
        code, _, _ = exec_cmd(f"ipcrm -s {sem_id}")
        if code != 0:
            log_and_echo_error("clear sem_id failed")
            exec_cmd("tail -f /dev/null", timeout=0)
        log_and_echo_info("clear sem_id success")


def prepare_certificate():
    if str(mes_ssl_switch) == "False":
        return

    certificate_dir = _paths.certificates_dir
    exec_cmd(f"mkdir -m 700 -p {certificate_dir}")

    ca_path = os.path.join(CERT_CONFIG_PATH, "ca.crt")
    crt_path = os.path.join(CERT_CONFIG_PATH, "mes.crt")
    key_path = os.path.join(CERT_CONFIG_PATH, "mes.key")

    cert_password_file = os.path.join(CERT_CONFIG_PATH, CERT_PASS)
    cert_password = ""
    if os.path.isfile(cert_password_file):
        with open(cert_password_file, "r") as f:
            cert_password = f.read().strip()

    exec_cmd(f'cp -arf "{ca_path}" "{certificate_dir}/ca.crt"')
    exec_cmd(f'cp -arf "{crt_path}" "{certificate_dir}/mes.crt"')
    exec_cmd(f'cp -arf "{key_path}" "{certificate_dir}/mes.key"')
    exec_cmd(f'echo "{cert_password}" > "{certificate_dir}/mes.pass"')
    exec_cmd(f'chown -hR "{ograc_user}":"{ograc_group}" "{certificate_dir}"')
    exec_cmd(f'su -s /bin/bash - "{ograc_user}" -c "chmod 600 {certificate_dir}/*"')

    tmp_path = os.environ.get("LD_LIBRARY_PATH", "")
    os.environ["LD_LIBRARY_PATH"] = f"{_paths.dbstor_lib}:{tmp_path}"
    resolve_pwd_py = os.path.join(CUR_PATH, "resolve_pwd.py")
    code, _, _ = exec_cmd(f'python3 -B "{resolve_pwd_py}" "resolve_check_cert_pwd" "{cert_password}"')
    os.environ["LD_LIBRARY_PATH"] = tmp_path
    if code != 0:
        log_and_echo_error("Cert file or passwd check failed.")
        exit_with_log()
    clear_sem_id()



def set_version_file():
    pkg_version = os.path.join(PKG_PATH, VERSION_FILE)
    if not os.path.isfile(pkg_version):
        log_and_echo_error(f"{VERSION_FILE} is not exist!")
        exit_with_log()

    if not check_version_file():
        if deploy_mode == "dbstor":
            exec_cmd(f'chown "{ograc_user}":"{ograc_group}" "{pkg_version}"')
            code, _, _ = exec_cmd(
                f'su -s /bin/bash - "{ograc_user}" -c "dbstor --copy-file --import --fs-name={storage_share_fs} '
                f'--source-dir={PKG_PATH} --target-dir=/ --file-name={VERSION_FILE}"'
            )
            if code != 0:
                log_and_echo_error("Execute dbstor tool command: --copy-file failed.")
                exit_with_log()
        else:
            shutil.copy2(pkg_version, os.path.join(VERSION_PATH, VERSION_FILE))

    if os.path.isfile(CMS_CONTAINER_FLAG):
        os.remove(CMS_CONTAINER_FLAG)


def check_only_start_file():
    if deploy_mode == "dbstor":
        code, out, _ = exec_cmd(
            f'su -s /bin/bash - "{ograc_user}" -c \'dbstor --query-file --fs-name={storage_share_fs} --file-dir=/\' | grep "onlyStart.file" | wc -l'
        )
        return out.strip() == "1"
    else:
        return os.path.isfile(os.path.join(VERSION_PATH, "onlyStart.file"))


def set_only_ograc_start_file():
    if not check_only_start_file():
        if deploy_mode == "dbstor":
            code, _, _ = exec_cmd(
                f'su -s /bin/bash - "{ograc_user}" -c \'dbstor --create-file --fs-name={storage_share_fs} --file-name=onlyStart.file\''
            )
            if code != 0:
                log_and_echo_error("Execute dbstor tool command: --create-file failed.")
                exit_with_log()
        else:
            touch(os.path.join(VERSION_PATH, "onlyStart.file"))



def execute_ograc_numa():
    """Run ograc-numa binding and create pod lock file."""
    ograc_numa_py = os.path.join(CUR_PATH, "ograc_numa.py")
    exec_cmd(f"ln -sf {ograc_numa_py} /usr/local/bin/ograc-numa")
    exec_cmd(f"chmod +x {ograc_numa_py}")

    code, pod_file_path, _ = exec_cmd(f"python3 {ograc_numa_py}")
    if code != 0:
        log_and_echo_error("Error occurred in ograc-numa execution.")
        exit_with_log()

    pod_file_path = pod_file_path.strip()
    if pod_file_path and not os.path.isfile(pod_file_path):
        touch(pod_file_path)

    if pod_file_path:
        exec_cmd(f'exec 200>"{pod_file_path}" && flock -n 200')

    bind_cpu_py = os.path.join(CUR_PATH, "../ograc/bind_cpu_config.py")
    if os.path.isfile(bind_cpu_py):
        exec_cmd(f"python3 {bind_cpu_py}")



def patch_deploy_param():
    """Replicate the shell sed operations on deploy_param.json."""
    config_file = os.path.join(CONFIG_PATH, CONFIG_NAME)
    opt_config_file = os.path.join(OPT_CONFIG_PATH, CONFIG_NAME)

    try:
        with open(config_file, "r") as f:
            data = json.load(f)
        user = data.get("deploy_user", "").split(":")[0] if ":" in data.get("deploy_user", "") else data.get("deploy_user", "")
    except Exception:
        user = ograc_user

    shutil.copy2(config_file, opt_config_file)

    deploy_mode_val = get_value("deploy_mode")

    if deploy_mode_val == "file":
        for fpath in [opt_config_file, config_file]:
            try:
                with open(fpath, "r") as f:
                    d = json.load(f)
                changed = False
                if "cluster_id" not in d:
                    d["cluster_id"] = "0"
                    changed = True
                if "cluster_name" not in d:
                    d["cluster_name"] = "ograc_file"
                    changed = True
                if "remote_cluster_name" not in d:
                    d["remote_cluster_name"] = "ograc_file"
                    changed = True
                if changed:
                    with open(fpath, "w") as f:
                        json.dump(d, f, indent=2)
            except Exception:
                pass

    for fpath in [config_file, opt_config_file]:
        try:
            with open(fpath, "r") as f:
                d = json.load(f)
            d["deploy_user"] = f"{user}:{user}"
            with open(fpath, "w") as f:
                json.dump(d, f, indent=2)
        except Exception:
            pass



def init_start():
    log_and_echo_info("Begin to pre-check the parameters.")
    code, _, _ = exec_cmd(f"python3 {PRE_INSTALL_PY_PATH} 'override' {CONFIG_PATH}/{CONFIG_NAME}", timeout=600)
    if code != 0:
        log_and_echo_error("parameters pre-check failed.")
        exit_with_log()
    log_and_echo_info("pre-check the parameters success.")

    code, _, _ = exec_cmd(f"sh {SCRIPT_PATH}/appctl.sh init_container", timeout=3600)
    if code != 0:
        log_and_echo_info("current dr action is recover already init dbstor, system exit.")
        exit_with_log()

    dr_action = get_value("dr_action")
    if dr_action == "recover":
        exec_cmd("tail -f /dev/null", timeout=0)

    exec_cmd(f"python3 {PRE_INSTALL_PY_PATH} 'sga_buffer_check'")

    check_init_status()

    execute_ograc_numa()

    container_upgrade_py = os.path.join(CUR_PATH, "container_upgrade.py")
    code, _, _ = exec_cmd(f"python3 {container_upgrade_py}", timeout=7200)
    if code != 0:
        if os.path.isfile(HEALTHY_FILE):
            os.remove(HEALTHY_FILE)
        exit_with_log()

    dr_setup = get_value("dr_deploy.dr_setup")
    dr_deploy_wrapper = os.path.join(CUR_PATH, "dr_deploy_wrapper.py")

    dr_deploy_sh_path = os.path.join(CUR_PATH, "dr_deploy_wrapper.py")
    exec_cmd(f"ln -sf {dr_deploy_sh_path} /usr/local/bin/dr-deploy")
    exec_cmd(f"chmod +x {dr_deploy_sh_path}")

    if str(dr_setup) == "True":
        ld_src = os.environ.get("LD_LIBRARY_PATH", "")
        os.environ["LD_LIBRARY_PATH"] = f"{_paths.dbstor_lib}:{ld_src}"
        dr_deploy_py = os.path.join(CUR_PATH, "dr_deploy.py")
        code, _, _ = exec_cmd(f'python3 "{dr_deploy_py}" "start"')
        if code != 0:
            log_and_echo_error("executing dr_deploy failed.")
            os.environ["LD_LIBRARY_PATH"] = ld_src
            exit_with_log()
        os.environ["LD_LIBRARY_PATH"] = ld_src
    else:
        dr_status_file = os.path.join(CONFIG_PATH, "dr_status.json")
        if os.path.isfile(dr_status_file):
            ld_src = os.environ.get("LD_LIBRARY_PATH", "")
            os.environ["LD_LIBRARY_PATH"] = f"{_paths.dbstor_lib}:{ld_src}"
            dr_deploy_py = os.path.join(CUR_PATH, "dr_deploy.py")
            code, dr_status_out, _ = exec_cmd(f'python3 "{dr_deploy_py}" "get_dr_status"')
            os.environ["LD_LIBRARY_PATH"] = ld_src

            if "Normal" in dr_status_out:
                log_and_echo_error("DR status is Normal. but dr_deploy=>dr_setup is False, please check config file.")
                exit_with_log()

        code, _, _ = exec_cmd(f"sh {SCRIPT_PATH}/appctl.sh start", timeout=3600)
        if code != 0:
            exit_with_log()
        set_only_ograc_start_file()

    set_version_file()

    touch(READINESS_FILE)



def exit_with_log():
    """On failure: cleanup gcc_file, backup logs, remove healthy probe, block forever."""
    if node_id == 0:
        if deploy_mode == "dbstor" and os.path.isfile(CMS_CONTAINER_FLAG):
            code, out, _ = exec_cmd(
                f'su -s /bin/bash - "{ograc_user}" -c \'dbstor --query-file --fs-name={storage_share_fs} --file-dir="gcc_home"\' | grep gcc_file | wc -l'
            )
            count = int(out.strip()) if out.strip().isdigit() else 0
            if count != 0:
                exec_cmd(f'su -s /bin/bash - "{ograc_user}" -c "cms gcc -del"')
        elif os.path.isfile(CMS_CONTAINER_FLAG) and os.path.isfile(gcc_file):
            import glob as glob_mod
            for f in glob_mod.glob(f"{gcc_file}*"):
                os.remove(f)

    log_backup_py = os.path.join(CUR_PATH, "log_backup.py")
    exec_cmd(f"python3 {log_backup_py} {cluster_name} {cluster_id} {node_id} {deploy_user} {storage_metadata_fs}")

    if os.path.isfile(HEALTHY_FILE):
        os.remove(HEALTHY_FILE)

    exec_cmd("tail -f /dev/null", timeout=0)



def process_logs():
    log_and_echo_info("ograc container initialization completed successfully.")
    logs_handler = _paths.logs_handler_execute
    while True:
        code, _, _ = exec_cmd(f"python3 {logs_handler}", timeout=7200)
        if code != 0:
            print("Error occurred in execute.py, retrying in 5 seconds...")
            time.sleep(5)
            continue
        time.sleep(3600)



def setup_kube_config():
    kube_dir = os.path.dirname(_paths.kube_config)
    exec_cmd(f"mkdir -p -m 755 {kube_dir}")
    exec_cmd(f'cp "{_paths.kube_config_src}" "{_paths.kube_config}"')
    exec_cmd(f'chmod 555 "{_paths.kube_config}"')



def main():
    touch(HEALTHY_FILE)

    pod_record_py = os.path.join(CUR_PATH, "pod_record.py")
    exec_cmd(f"python3 {pod_record_py}")

    update_policy_py = os.path.join(CUR_PATH, "update_policy_params.py")
    code, out, _ = exec_cmd(f"python3 {update_policy_py}")
    if code != 0:
        log_and_echo_info(f"update policy params failed, details: {out}")
        sys.exit(1)

    patch_deploy_param()

    try:
        resource.setrlimit(resource.RLIMIT_CORE, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
    except Exception:
        pass
    try:
        resource.setrlimit(resource.RLIMIT_MEMLOCK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
    except Exception:
        pass

    setup_kube_config()

    wait_config_done(node_domain)
    check_container_context()
    prepare_kmc_conf()
    prepare_certificate()
    mount_fs()
    init_start()
    process_logs()


if __name__ == "__main__":
    main()
