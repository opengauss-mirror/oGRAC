#!/usr/bin/env python3
import argparse
import os
import re
import subprocess
import sys
import time
from datetime import datetime

CUR_DIR = os.path.dirname(os.path.abspath(__file__))

if CUR_DIR not in sys.path:
    sys.path.insert(0, CUR_DIR)

from config import get_config


def exec_popen(cmd, timeout=600):
    """Execute shell command using subprocess.Popen"""
    proc = subprocess.Popen(
        ["bash", "-c", cmd],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        stdout_b, stderr_b = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        return -1, "", f"Timeout after {timeout}s"
    return (
        proc.returncode,
        stdout_b.decode(errors="replace").strip(),
        stderr_b.decode(errors="replace").strip(),
    )


def run_shell_as_user(cmd, user, timeout=600):
    """Run shell command as specified user"""
    full_cmd = f'su -s /bin/bash - {user} -c "{cmd}"'
    return exec_popen(full_cmd, timeout=timeout)


def load_report_cnf(cnf_path):
    config = {}
    if not os.path.exists(cnf_path):
        return config

    with open(cnf_path, encoding="utf-8") as f:
        content = f.read()

    patterns = {
        "system_user_name": r'system_user_name="(.*?)"',
        "ogsql_user_name": r'ogsql_user_name="(.*?)"',
        "ogsql_user_passwd": r'ogsql_user_passwd="(.*?)"',
        "ogsql_server_ip": r'ogsql_server_ip="(.*?)"',
        "ogsql_server_port": r'ogsql_server_port="(.*?)"',
        "ogsql_snapshot_time": r'ogsql_snapshot_time=(\d+)',
        "report_output_dir": r'report_output_dir="(.*?)"',
    }

    for key, pattern in patterns.items():
        m = re.search(pattern, content)
        if m:
            if key == "ogsql_snapshot_time":
                config[key] = int(m.group(1))
            else:
                config[key] = m.group(1)

    return config


def resolve_runtime_report_cnf(cfg, report_cnf, args):
    resolved = dict(report_cnf)
    resolved_port = args.ogsql_server_port or cfg.get_deploy_param(
        "ograc_port", report_cnf.get("ogsql_server_port", "1611")
    )
    resolved["ogsql_server_port"] = str(resolved_port)

    resolved_output_dir = args.report_output_dir or report_cnf.get("report_output_dir", "")
    if not resolved_output_dir:
        resolved_output_dir = cfg.paths.report_output_dir
    resolved["report_output_dir"] = resolved_output_dir

    resolved_system_user = args.system_user_name or report_cnf.get("system_user_name", "")
    if not resolved_system_user:
        resolved_system_user = cfg.user
    resolved["system_user_name"] = resolved_system_user
    return resolved


def ensure_dir(path, mode=0o770, owner=""):
    if not os.path.exists(path):
        os.makedirs(path, mode=mode)
    else:
        os.chmod(path, mode)

    if owner:
        rc, _, err = exec_popen(f"chown -h {owner} {path}")
        if rc != 0:
            print(f"Warning: Failed to chown {path}: {err}", file=sys.stderr)


def gen_wsr_report(cfg, report_cnf):
    ograc_user = cfg.user
    ogsql_user_name = report_cnf.get("ogsql_user_name", "sys")
    ogsql_user_passwd = report_cnf.get("ogsql_user_passwd", "")
    ogsql_server_ip = report_cnf.get("ogsql_server_ip", "127.0.0.1")
    ogsql_server_port = report_cnf.get("ogsql_server_port", "1611")
    ogsql_snapshot_time = report_cnf.get("ogsql_snapshot_time", 60)
    report_output_dir = report_cnf.get("report_output_dir", cfg.paths.report_output_dir)

    host_name = os.uname().nodename if hasattr(os, 'uname') else os.environ.get("HOSTNAME", "localhost")
    date_time = datetime.now().strftime("%Y%m%d%H%M%S")

    if ogsql_user_passwd:
        conn_str = f"{ogsql_user_name}/{ogsql_user_passwd}@{ogsql_server_ip}:{ogsql_server_port}"
    else:
        conn_str = f"{ogsql_user_name}@{ogsql_server_ip}:{ogsql_server_port}"

    wsr_list_cmd = f"ogsql {conn_str} -q -c 'wsr list'"
    rc, wsr_list_out, err = run_shell_as_user(wsr_list_cmd, ograc_user)
    if rc != 0:
        print(f"Error: Failed to list WSR snapshots: {err}", file=sys.stderr)
        return False

    kmc_log = "KmcCheckKmcCtx" in wsr_list_out

    snapshot_cmd = f"ogsql {conn_str} -q -c 'CALL WSR$CREATE_SNAPSHOT'"
    rc, _, err = run_shell_as_user(snapshot_cmd, ograc_user)
    if rc != 0:
        print(f"Error: Failed to create first snapshot: {err}", file=sys.stderr)
        return False

    time.sleep(ogsql_snapshot_time)

    rc, _, err = run_shell_as_user(snapshot_cmd, ograc_user)
    if rc != 0:
        print(f"Error: Failed to create second snapshot: {err}", file=sys.stderr)
        return False

    rc, wsr_list_out, err = run_shell_as_user(wsr_list_cmd, ograc_user)
    if rc != 0:
        print(f"Error: Failed to list WSR snapshots after creation: {err}", file=sys.stderr)
        return False

    lines = wsr_list_out.split('\n')
    
    if kmc_log:
        if len(lines) >= 12:
            line_12 = lines[11].strip() if len(lines) > 11 else ""
            line_11 = lines[10].strip() if len(lines) > 10 else ""
            snap_id_1 = line_12.split()[0] if line_12 and len(line_12.split()) > 0 else None
            snap_id_2 = line_11.split()[0] if line_11 and len(line_11.split()) > 0 else None
        else:
            print(f"Error: Not enough lines in wsr list output (expected >=12, got {len(lines)})", file=sys.stderr)
            return False
    else:
        if len(lines) >= 11:
            line_11 = lines[10].strip() if len(lines) > 10 else ""
            line_10 = lines[9].strip() if len(lines) > 9 else ""
            snap_id_1 = line_11.split()[0] if line_11 and len(line_11.split()) > 0 else None
            snap_id_2 = line_10.split()[0] if line_10 and len(line_10.split()) > 0 else None
        else:
            print(f"Error: Not enough lines in wsr list output (expected >=11, got {len(lines)})", file=sys.stderr)
            return False

    if not snap_id_1 or not snap_id_2:
        print("Error: Failed to extract snapshot IDs", file=sys.stderr)
        return False

    report_file = os.path.join(report_output_dir, f"ograc_wsr_{host_name}_{date_time}.html")
    report_cmd = f'ogsql {conn_str} -q -c \'wsr {snap_id_1} {snap_id_2} "{report_file}"\''
    rc, _, err = run_shell_as_user(report_cmd, ograc_user)
    if rc != 0:
        print(f"Error: Failed to generate WSR report: {err}", file=sys.stderr)
        return False

    print(f"WSR report generated successfully: {report_file}")
    return True


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=os.path.join(CUR_DIR, "report.cnf"))
    parser.add_argument("--ogsql-server-port", dest="ogsql_server_port", default="")
    parser.add_argument("--report-output-dir", dest="report_output_dir", default="")
    parser.add_argument("--system-user-name", dest="system_user_name", default="")
    return parser.parse_args()


def main():
    args = parse_args()
    cfg = get_config()
    report_cnf = resolve_runtime_report_cnf(cfg, load_report_cnf(args.config), args)
    report_output_dir = report_cnf["report_output_dir"]
    system_user_name = report_cnf["system_user_name"]
    ograc_common_group = cfg.common_group

    ensure_dir(report_output_dir, mode=0o770, owner=f"{system_user_name}:{ograc_common_group}")

    if not gen_wsr_report(cfg, report_cnf):
        print("Error: Failed to generate WSR report", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
