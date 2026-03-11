"""
ograc_exporter 核心控制器（业务用户身份运行）

按 REFACTOR_SPEC 要求，把原 start.sh / stop.sh / check_status.sh 中的
shell 逻辑全部 Python 化。不调用任何旧 shell 脚本。
"""

import argparse
import os
import subprocess
import sys
import tempfile
import time

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
if CUR_DIR not in sys.path:
    sys.path.insert(0, CUR_DIR)

from config import get_config
from log_config import get_logger

LOG = get_logger()
_cfg = get_config()
paths = _cfg.paths


def _log_script_output(output):
    if not output:
        return
    for line in output.splitlines():
        if line.strip():
            LOG.info(line)


def _exporter_running():
    """检查 ograc_exporter 的 execute.py 是否在运行"""
    try:
        result = subprocess.run(
            ["bash", "-c",
             f'ps -ef | grep "python3 {paths.execute_py}" | grep -v grep | awk \'{{print $2}}\''],
            capture_output=True, text=True, timeout=30,
        )
        pid = result.stdout.strip()
        return bool(pid)
    except Exception:
        return False


def _run_start_script(start_script, process_name, is_running, timeout=60):
    with tempfile.TemporaryFile() as tmp:
        proc = subprocess.Popen(
            ["bash", start_script],
            stdout=tmp, stderr=subprocess.STDOUT,
        )
        try:
            rc = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            tmp.seek(0)
            output = tmp.read().decode(errors="replace").strip()
            _log_script_output(output)
            if is_running():
                LOG.info(
                    "%s start script timed out but process is already running, treat as success",
                    process_name,
                )
                return
            raise RuntimeError(f"{os.path.basename(start_script)} timed out after {timeout}s")

        tmp.seek(0)
        output = tmp.read().decode(errors="replace").strip()
        _log_script_output(output)
        if rc != 0:
            if is_running():
                LOG.info(
                    "%s start script returned rc=%s but process is already running, treat as success",
                    process_name, rc,
                )
                return
            raise RuntimeError(f"{os.path.basename(start_script)} failed (rc={rc})")



def action_check_status():
    """原 check_status.sh 逻辑（22 行 shell → Python）"""
    if _exporter_running():
        LOG.info("ograc_exporter is running")
        return
    raise RuntimeError("ograc_exporter is not running")


def action_start():
    """原 start.sh 逻辑（39 行 shell → Python）

    调用服务层 start_ograc_exporter.sh（这是组件二进制自带的启动脚本，
    不属于部署脚本，需保留调用）
    """
    LOG.info("Begin to start og_exporter")

    start_script = paths.start_script
    if not os.path.isfile(start_script):
        raise FileNotFoundError(f"start script not found: {start_script}")

    _run_start_script(start_script, "ograc_exporter", _exporter_running, timeout=60)
    time.sleep(3)

    if not _exporter_running():
        raise RuntimeError("ograc_exporter failed to start (process not found after 3s)")

    LOG.info("Success to start og_exporter")


def action_stop():
    """原 stop.sh 逻辑（36 行 shell → Python）"""
    LOG.info("Begin to stop og_exporter")

    if not _exporter_running():
        LOG.info("og_exporter has been offline already")
        return

    stop_script = paths.stop_script
    if not os.path.isfile(stop_script):
        raise FileNotFoundError(f"stop script not found: {stop_script}")

    proc = subprocess.Popen(
        ["bash", stop_script],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    out_b, _ = proc.communicate(timeout=60)
    output = out_b.decode(errors="replace").strip()
    if output:
        LOG.info(output)

    if proc.returncode != 0:
        raise RuntimeError(f"stop_ograc_exporter.sh failed (rc={proc.returncode})")

    LOG.info("Success to stop og_exporter")



ACTION_MAP = {
    "start": action_start,
    "stop": action_stop,
    "check_status": action_check_status,
}


def main():
    parser = argparse.ArgumentParser(description="ograc_exporter controller (refactored)")
    parser.add_argument("action", choices=list(ACTION_MAP.keys()))
    args, _ = parser.parse_known_args()

    fn = ACTION_MAP[args.action]
    fn()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        LOG.error(str(e))
        sys.exit(1)
