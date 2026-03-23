#!/usr/bin/env python3
"""Container deploy policy param update (simplified). Only default policy, write to deploy_param.json."""
import os
import json
import stat
import sys

CUR_PATH = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.join(CUR_PATH, ".."))

from config import get_config
from om_log import LOGGER as LOG

_cfg = get_config()


def _read_deploy_param():
    config_dir = os.path.join(_cfg.paths.ograc_home, "config")
    init_conf = os.path.join(config_dir, "container_conf", "init_conf", "deploy_param.json")
    try:
        with open(init_conf, 'r', encoding='utf8') as f:
            return json.load(f)
    except Exception as e:
        LOG.error("load %s error: %s", init_conf, e)
        return None


def _write_deploy_param(data):
    dst = os.path.join(_cfg.paths.config_dir, "deploy_param.json")
    flags = os.O_RDWR | os.O_CREAT | os.O_TRUNC
    modes = stat.S_IRWXU | stat.S_IROTH | stat.S_IRGRP
    with os.fdopen(os.open(dst, flags, modes), 'w') as f:
        f.write(json.dumps(data, indent=4))


def main():
    source = _read_deploy_param()
    if source is None:
        raise RuntimeError("Failed to read deploy_param.json")

    policy = source.get("deploy_policy", "")
    if policy not in ("", "default"):
        LOG.error("Unsupported deploy policy '%s' (only 'default' is supported)", policy)
        raise RuntimeError(f"Unsupported deploy policy: {policy}")

    source["deploy_policy"] = "default"
    _write_deploy_param(source)
    LOG.info("deploy policy set to default")


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        exit(str(e))
