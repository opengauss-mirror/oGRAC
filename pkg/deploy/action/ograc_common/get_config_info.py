#!/usr/bin/env python3
"""Deploy parameter lookup."""

import sys
import os

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, CUR_DIR)

from config import cfg as _cfg


def get_value(param):
    if param in ("deploy_user", "ograc_user"):
        return _cfg.user
    if param in ("deploy_group", "ograc_group"):
        return _cfg.group
    return _cfg.get_deploy_param(param, "")


if __name__ == "__main__":
    _param = sys.argv[1]
    res = get_value(_param)
    print(res)
