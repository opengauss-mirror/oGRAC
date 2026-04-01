#!/usr/bin/env python3
"""
dr_deploy_wrapper.py (Pythonized from dr_deploy.sh)

Simple wrapper that sets LD_LIBRARY_PATH and invokes dr_deploy.py.
"""
import os
import sys
import subprocess

CUR_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, CUR_PATH)

from config import get_config

_cfg = get_config()
_paths = _cfg.paths


def main():
    ld_path_src = os.environ.get("LD_LIBRARY_PATH", "")
    os.environ["LD_LIBRARY_PATH"] = f"{_paths.dbstor_lib}:{ld_path_src}"

    dr_deploy_py = os.path.join(CUR_PATH, "dr_deploy.py")
    result = subprocess.run(
        [sys.executable, dr_deploy_py] + sys.argv[1:],
        env=os.environ.copy()
    )

    os.environ["LD_LIBRARY_PATH"] = ld_path_src

    if result.returncode != 0:
        print("executing dr_deploy failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
