#!/usr/bin/env python3
"""ograc_exporter controller."""

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
    """Check if ograc_exporter execute.py is running."""
    try:
        result = subprocess.run(
            ["bash", "-c",
             f'ps -ef | grep "python3 {paths.execute_py}" | grep -v grep | awk \'{{print $2}}\''],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True, timeout=30,
        )
        pid = result.stdout.strip()
        return bool(pid)
    except Exception:
        return False


def _read_log_tail(filepath, n=30):
    try:
        if not os.path.isfile(filepath):
            return ""
        with open(filepath, "r", errors="replace") as f:
            lines = f.readlines()
            return "".join(lines[-n:])
    except Exception:
        return ""


def _gather_start_diagnostics():
    diag_files = [paths.log_file]
    og_om_log = os.path.join(paths.ograc_home, "log", "og_om", "exporter.log")
    if og_om_log != paths.log_file:
        diag_files.append(og_om_log)
    parts = []
    for fpath in diag_files:
        tail = _read_log_tail(fpath)
        if tail.strip():
            parts.append(f"--- {fpath} (last lines) ---\n{tail}")
    return "\n".join(parts)


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
    """Check if ograc_exporter is running."""
    if _exporter_running():
        LOG.info("ograc_exporter is running")
        return
    raise RuntimeError("ograc_exporter is not running")


def action_start():
    """Start ograc_exporter via component start script."""
    LOG.info("Begin to start og_exporter")

    start_script = paths.start_script
    if not os.path.isfile(start_script):
        raise FileNotFoundError(f"start script not found: {start_script}")

    try:
        _run_start_script(start_script, "ograc_exporter", _exporter_running, timeout=60)
    except RuntimeError as e:
        diag = _gather_start_diagnostics()
        if diag:
            raise RuntimeError(f"{e}\n{diag}") from None
        raise

    time.sleep(3)

    if not _exporter_running():
        diag = _gather_start_diagnostics()
        msg = "ograc_exporter failed to start (process not found after 3s)"
        if diag:
            msg += f"\n{diag}"
        raise RuntimeError(msg)

    LOG.info("Success to start og_exporter")


def action_stop():
    """Stop ograc_exporter via component stop script."""
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
    parser = argparse.ArgumentParser(description="ograc_exporter controller")
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
