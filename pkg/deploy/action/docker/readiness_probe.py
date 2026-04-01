#!/usr/bin/env python3
"""
readiness_probe.py (Pythonized from readiness_probe.sh)

Container readiness probe logic.
Exit 0 = ready, Exit 1 = not ready.
"""
import os
import sys
import subprocess
import re

CUR_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, CUR_PATH)

from config import get_config, get_value
from docker_common.docker_log import log_info, log_warn, log_error

_cfg = get_config()
_paths = _cfg.paths


def exec_popen(cmd, timeout=30):
    """Run a shell command and return (returncode, stdout, stderr)."""
    try:
        proc = subprocess.Popen(
            ["bash"], shell=False,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        proc.stdin.write(cmd.encode())
        proc.stdin.write(os.linesep.encode())
        stdout, stderr = proc.communicate(timeout=timeout)
        return proc.returncode, stdout.decode().strip(), stderr.decode().strip()
    except subprocess.TimeoutExpired:
        proc.kill()
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)


def get_process_pid(pattern):
    """Return PID of the first matching process or None."""
    code, out, _ = exec_popen(f"pgrep -f '{pattern}'")
    if code == 0 and out.strip():
        return out.strip().splitlines()[0]
    return None


def handle_failure(ograc_user, node_id):
    """Handle readiness failure: possibly trigger delete_unready_pod."""
    cms_pid = get_process_pid("cms.*server.*start")
    if cms_pid:
        code, out, _ = exec_popen(
            f"su -s /bin/bash - {ograc_user} -c 'source ~/.bashrc && cms stat' | grep 'db' | "
            f"awk '{{if($5==\"OFFLINE\" && $1=={node_id}){{print $5}}}}' | wc -l"
        )
        cms_enable = _paths.cms_enable
        if os.path.isfile(cms_enable):
            try:
                manual_stop_count = int(out.strip()) if out.strip().isdigit() else 0
            except ValueError:
                manual_stop_count = 0
            if manual_stop_count == 1:
                log_info("CMS is manually stopped. Exiting.")
                sys.exit(1)

    if os.path.isfile(_paths.readiness_file):
        delete_script = os.path.join(CUR_PATH, "delete_unready_pod.py")
        subprocess.run([sys.executable, delete_script])
    sys.exit(1)


def main():
    ograc_user = get_value("deploy_user")
    deploy_user = get_value("deploy_user")
    run_mode = get_value("M_RUNING_MODE")
    node_id = get_value("node_id")

    install_step = ""
    try:
        cms_config_info = os.path.join(CUR_PATH, "../cms/get_config_info.py")
        if os.path.isfile(cms_config_info):
            code, out, _ = exec_popen(f"python3 {cms_config_info} install_step")
            if code == 0:
                install_step = out.strip()
    except Exception:
        pass

    if os.path.isfile(_paths.stop_enable_file) or install_step != "3":
        sys.exit(1)

    if os.path.isfile(_paths.cms_res_disable):
        log_info("DB is manually stopped.")
        sys.exit(1)

    if len(sys.argv) > 1 and sys.argv[1] == "startup-check":
        if os.path.isfile(_paths.readiness_file):
            sys.exit(0)
        else:
            sys.exit(1)

    if not os.path.isfile(_paths.readiness_file):
        sys.exit(1)

    ogracd_pid = get_process_pid("ogracd")
    if not ogracd_pid and run_mode == "ogracd_in_cluster":
        log_warn("ogracd process not running in cluster mode.")
        handle_failure(ograc_user, node_id)

    cms_pid = get_process_pid("cms.*server.*start")
    if not cms_pid:
        log_warn("CMS process not found.")
        handle_failure(ograc_user, node_id)

    nid_plus1 = int(node_id) + 1 if str(node_id).isdigit() else 1
    code, work_stat, _ = exec_popen(
        f"su -s /bin/bash - {ograc_user} -c 'cms stat' | awk -v nid={nid_plus1} 'NR==nid+1 {{print $6}}'"
    )
    if work_stat.strip() != "1":
        log_warn("Work status is not 1.")
        handle_failure(ograc_user, node_id)

    ograc_daemon_pid = get_process_pid("ograc_daemon")
    if not ograc_daemon_pid:
        log_info("ograc daemon not found. Attempting to start.")
        if os.path.isfile(_paths.stop_enable_file):
            log_info("ograc daemon not found. because to stop.")
            sys.exit(1)
        subprocess.run(["bash", _paths.ograc_service_sh, "start"])
        ograc_daemon_pid = get_process_pid("ograc_daemon")
        if not ograc_daemon_pid:
            log_error("Failed to start ograc daemon.")
            handle_failure(ograc_user, node_id)
        else:
            log_info("ograc daemon started successfully.")

    sys.exit(0)


if __name__ == "__main__":
    main()
