#!/usr/bin/env python3
"""
check_link_cnt.py — Python equivalent of check_link_cnt.sh

Checks whether dbstor has redundant links (LinkCnt >= 2).
"""
import os
import subprocess
import sys
import time

_CUR_DIR = os.path.dirname(os.path.abspath(__file__))
_INSPECTION_DIR = os.path.abspath(os.path.join(_CUR_DIR, "../.."))
sys.path.insert(0, _INSPECTION_DIR)

from config import get_config

_cfg = get_config()
_paths = _cfg.paths

DBSTOOL_PATH = _paths.dbstor_home
LOG_NAME = "cgwshowdev.log"
MAX_RETRIES = 5
MIN_LINK_CNT = 2


def use_cstool_query_connection():
    """Run diagsh cgw showdev and check link count."""
    cstool_type = os.environ.get("CSTOOL_TYPE", "")
    set_type = ""
    if cstool_type in ("release", "asan"):
        set_type = "--set-cli"

    tools_dir = os.path.join(DBSTOOL_PATH, "tools")
    log_path = os.path.join(DBSTOOL_PATH, LOG_NAME)

    for _ in range(MAX_RETRIES):
        cmd_parts = ["./diagsh"]
        if set_type:
            cmd_parts.append(set_type)
        cmd_parts.extend(['--attach=dbstore_client_350', '--cmd=cgw showdev'])
        cmd = " ".join(cmd_parts)

        try:
            proc = subprocess.Popen(
                ["bash", "-c", cmd],
                cwd=tools_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            output, _ = proc.communicate(timeout=60)
            output_str = output.decode("utf-8", errors="replace")

            with open(log_path, "w") as f:
                f.write(output_str)

            lines = output_str.splitlines()
            in_section = False
            link_cnt = 0
            for line in lines:
                if "LinkCnt" in line:
                    in_section = True
                    continue
                if in_section and "0x" in line:
                    link_cnt += 1

            if link_cnt >= MIN_LINK_CNT:
                return 0
        except Exception:
            pass

        time.sleep(1)

    return 1


def main():
    ret = use_cstool_query_connection()
    print(str(ret))
    sys.exit(ret)


if __name__ == "__main__":
    main()
