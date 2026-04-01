#!/usr/bin/env python3
"""
upgrade_systable.py (Pythonized from upgrade_systable.sh)

Usage:
    python3 upgrade_systable.py <node_ip> <py_path> <old_initdb> <new_initdb> <sqls_path>
"""
import os
import sys
import subprocess
import getpass

CUR_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, CUR_PATH)

from config import get_config

_cfg = get_config()
_paths = _cfg.paths

OGRACD_PORT0 = "1611"


def exec_popen(cmd, timeout=1800):
    """Run a bash command, return (returncode, stdout, stderr)."""
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


def run_sql_process(py_path, task, **kwargs):
    """Call sql_process.py with given task and arguments."""
    args_str = " ".join(f"--{k}={v}" for k, v in kwargs.items())
    cmd = f"python {py_path}/sql_process.py -t {task} {args_str}"
    code, stdout, stderr = exec_popen(cmd)
    return code, stdout, stderr


def main():
    if len(sys.argv) < 6:
        print("Usage: upgrade_systable.py <node_ip> <py_path> <old_initdb> <new_initdb> <sqls_path>")
        sys.exit(1)

    os.environ["OGRACD_PORT0"] = OGRACD_PORT0
    node_ip = sys.argv[1]
    py_path = sys.argv[2]
    old_initdb = sys.argv[3]
    new_initdb = sys.argv[4]
    sqls_path = sys.argv[5]

    print("upgrade systable...")

    print("step1: upgrade systable check initdb...")
    code, out, err = run_sql_process(
        py_path, "check-initdb",
        **{"old-initdb": old_initdb, "new-initdb": new_initdb}
    )
    if out:
        for line in out.splitlines():
            if line.strip() != "'TABLESPACE' is not in list":
                print("upgrade systable check initdb failed")
                print(line)
                sys.exit(1)

    print("step2: upgrade systable check white list...")
    code, out, err = run_sql_process(
        py_path, "check-whitelist",
        **{"sqls-path": sqls_path}
    )
    if out:
        print("upgrade systable check white list failed")
        print(out)
        sys.exit(1)

    print("step3: upgrade systable generate upgrade sqls...")
    code, out, err = run_sql_process(
        py_path, "generate",
        **{"old-initdb": old_initdb, "new-initdb": new_initdb,
           "outdir": sqls_path, "sqls-path": sqls_path}
    )
    if out:
        print("upgrade systable generate upgrade sqls failed")
        print(out)
        sys.exit(1)

    upgrade_sql_file = os.path.join(sqls_path, "upgradeFile.sql")
    if not os.path.isfile(upgrade_sql_file) or not os.access(upgrade_sql_file, os.R_OK):
        print("upgrade systable generate upgrade sqls failed")
        sys.exit(1)

    print("step4: upgrade systable execute upgrade sqls...")
    user_pwd = sys.stdin.readline().strip() if not sys.stdin.isatty() else getpass.getpass("Please Input SYS_PassWord: ")

    resolve_pwd_py = os.path.join(CUR_PATH, "resolve_pwd.py")
    cmd = (
        f"echo -e '{sqls_path}\\n{node_ip}\\n{OGRACD_PORT0}' | "
        f"python3 -B {resolve_pwd_py} run_upgrade_modify_sys_tables_ogsql {user_pwd}"
    )
    code, out, err = exec_popen(cmd)
    if code != 0:
        print(f"upgrade systable execute upgrade sql failed")
        print(out)
        sys.exit(1)

    print("upgrade systable success")


if __name__ == "__main__":
    main()
