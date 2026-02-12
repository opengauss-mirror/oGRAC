"""
dbstor 核心控制器（业务用户身份运行）

把原 install.sh / uninstall.sh / backup.sh 中用户态逻辑 Python 化。
实际业务逻辑委托到原有 dbstor_install.py / dbstor_uninstall.py / dbstor_backup.py
以子进程方式调用（进程隔离）。
"""

import argparse
import os
import subprocess
import sys

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
if CUR_DIR not in sys.path:
    sys.path.insert(0, CUR_DIR)

from config import get_config
from log_config import get_logger

LOG = get_logger()
_cfg = get_config()
paths = _cfg.paths

LEGACY_DIR = os.path.abspath(os.path.join(CUR_DIR, "..", "dbstor"))


def _run_legacy_py(script_name, *args, timeout=1800, env_extra=None):
    """以子进程方式调用旧 Python 脚本"""
    script = os.path.join(LEGACY_DIR, script_name)
    if not os.path.isfile(script):
        raise FileNotFoundError(f"Legacy script not found: {script}")
    cmd = [sys.executable, "-B", script] + list(args)
    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = f"{paths.lib_dir}:{env.get('LD_LIBRARY_PATH', '')}"
    if env_extra:
        env.update(env_extra)
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        cwd=LEGACY_DIR, env=env,
    )
    try:
        out_b, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise RuntimeError(f"{script_name} timed out after {timeout}s")
    output = out_b.decode(errors="replace").strip()
    if output:
        LOG.info(output)
    if proc.returncode != 0:
        raise RuntimeError(f"{script_name} failed (rc={proc.returncode})")


def action_install():
    """原 install.sh Python 化"""
    LOG.info("Begin dbstor install (user context)")
    env_extra = {"LD_LIBRARY_PATH": f"{paths.lib_dir}:{os.environ.get('LD_LIBRARY_PATH', '')}"}
    _run_legacy_py("dbstor_install.py", timeout=_cfg.timeout.get("install"), env_extra=env_extra)
    LOG.info("dbstor install success")


def action_uninstall(uninstall_type="", force=""):
    """原 uninstall.sh Python 化"""
    LOG.info("Begin dbstor uninstall")
    args = [a for a in (uninstall_type, force) if a]
    _run_legacy_py("dbstor_uninstall.py", *args, timeout=_cfg.timeout.get("uninstall"))
    LOG.info("dbstor uninstall success")


def action_backup():
    """原 backup.sh Python 化"""
    LOG.info("Begin dbstor backup")
    _run_legacy_py("dbstor_backup.py", timeout=_cfg.timeout.get("backup"))
    LOG.info("dbstor backup success")


def action_init_container():
    """原 init_container.sh Python 化"""
    LOG.info("Begin dbstor init_container")
    p = paths
    dorado_dir = p.container_dorado_dir
    user_file = os.path.join(dorado_dir, "dbstorUser")
    pwd_file = os.path.join(dorado_dir, "dbstorPwd")

    dbstor_user = ""
    dbstor_pwd = ""
    if os.path.isfile(user_file):
        with open(user_file, "r") as f:
            dbstor_user = f.read().strip()
    if os.path.isfile(pwd_file):
        with open(pwd_file, "r") as f:
            dbstor_pwd = f.read().strip()

    local_conf = p.local_dbstor_conf
    os.makedirs(local_conf, mode=0o750, exist_ok=True)
    src_ini = os.path.join(p.tools_dir, "dbstor_config.ini")
    if os.path.isfile(src_ini):
        import shutil
        shutil.copy2(src_ini, os.path.join(local_conf, "dbstor_config.ini"))

    args = []
    if dbstor_user:
        args.extend(["--user", dbstor_user])
    if dbstor_pwd:
        args.extend(["--pwd", dbstor_pwd])
    _run_legacy_py("init_unify_config.py", *args, timeout=_cfg.timeout.get("init_container"))
    LOG.info("dbstor init_container success")


def action_update_config():
    """原 update.sh Python 化"""
    LOG.info("Begin dbstor update_config")
    env_extra = {"LD_LIBRARY_PATH": f"{paths.lib_dir}:{os.environ.get('LD_LIBRARY_PATH', '')}"}
    _run_legacy_py("update_dbstor_config.py", timeout=_cfg.timeout.get("update_config"),
                    env_extra=env_extra)
    LOG.info("dbstor update_config success")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--act", required=True,
                        choices=["install", "uninstall", "backup", "init_container",
                                 "update_config"])
    parser.add_argument("--uninstall-type", default="")
    parser.add_argument("--force", default="")
    args = parser.parse_args()

    func_map = {
        "install": action_install,
        "uninstall": lambda: action_uninstall(args.uninstall_type, args.force),
        "backup": action_backup,
        "init_container": action_init_container,
        "update_config": action_update_config,
    }
    func_map[args.act]()


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        LOG.error(str(err))
        sys.exit(1)
