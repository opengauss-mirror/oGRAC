#!/usr/bin/env python3
"""og_om core controller."""

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


def _ogmgr_running():
    """Check if ogmgr uds_server.py is running."""
    try:
        result = subprocess.run(
            ["bash", "-c",
             f'ps -ef | grep "{paths.ogmgr_uds_server}" | grep python | grep -v grep'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True, timeout=30,
        )
        return bool(result.stdout.strip())
    except Exception:
        return False


def _run_start_script(start_sh, process_name, is_running, timeout=120):
    with tempfile.TemporaryFile() as tmp:
        proc = subprocess.Popen(
            ["bash", start_sh],
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
            raise RuntimeError(f"{os.path.basename(start_sh)} timed out after {timeout}s")

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
            raise RuntimeError(f"{os.path.basename(start_sh)} failed (rc={rc})")



def action_check_status():
    """Check ogmgr service status."""
    if _ogmgr_running():
        LOG.info("ogmgr is running")
        return
    raise RuntimeError("ogmgr is not running")


def action_start():
    """Start ogmgr service."""
    LOG.info("Begin to start ogmgr")

    start_sh = paths.start_ogmgr_sh
    if not os.path.isfile(start_sh):
        raise FileNotFoundError(f"start script not found: {start_sh}")

    _run_start_script(start_sh, "ogmgr", _ogmgr_running, timeout=120)
    time.sleep(3)
    if not _ogmgr_running():
        raise RuntimeError("ogmgr failed to start (process not found after 3s)")
    LOG.info("ogmgr start done")


def action_stop():
    """Stop ogmgr service."""
    LOG.info("Begin to stop ogmgr")

    if not _ogmgr_running():
        LOG.info("ogmgr has been offline already")
        return

    stop_sh = paths.stop_ogmgr_sh
    if not os.path.isfile(stop_sh):
        raise FileNotFoundError(f"stop script not found: {stop_sh}")

    proc = subprocess.Popen(
        ["bash", stop_sh],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    out_b, _ = proc.communicate(timeout=120)
    output = out_b.decode(errors="replace").strip()
    if output:
        LOG.info(output)

    if proc.returncode != 0:
        raise RuntimeError(f"stop_ogmgr.sh failed (rc={proc.returncode})")

    LOG.info("ogmgr stop done")



ACTION_MAP = {
    "start": action_start,
    "stop": action_stop,
    "check_status": action_check_status,
}


def main():
    parser = argparse.ArgumentParser(description="og_om controller")
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
