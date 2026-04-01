#!/usr/bin/env python3

import os
import json
import sys
from pathlib import Path

_CUR_DIR = os.path.dirname(os.path.abspath(__file__))
_INSPECTION_DIR = os.path.abspath(os.path.join(_CUR_DIR, "../.."))
sys.path.insert(0, _INSPECTION_DIR)

from config import get_config
from log_tool import setup
from common_func import _exec_popen

_cfg = get_config()
_paths = _cfg.paths


def fetch_cms_version(logger):
    logger.info("cms version check start!")
    cmd = "source ~/.bashrc && cms -help |head -n 1 | grep -oP \"\K\d+\.\d+\""
    ret_code, output, stderr = _exec_popen(cmd)
    if ret_code:
        logger.error("get cms help information failed, std_err: %s", stderr)
    cmd_yml = "cat %s | grep -oP 'Version: \K\d+\.\d+'" % _paths.versions_yml
    ret_code_yml, output_yml, stderr_yml = _exec_popen(cmd_yml)
    if ret_code_yml != 0:
        logger.error("Get cms version failed.")
        raise Exception("Get cms version failed.")
    version = output.strip()
    result_json = {}
    result_json['data'] = {}
    result_json["error"] = {}
    result_json["error"]["code"] = 0
    result_json["error"]["description"] = ""
    result_json["data"]["RESULT"] = output
    if version != output_yml:
        logger.error("cms version is different from the version.yml")
        result_json["error"]["code"] = 1
        result_json["error"]["description"] = "get cms help information failed, std_err " \
                                              "or cms version is different from the version.yml"
    logger.info("cms version check succ!")
    return (result_json)


def fetch_cls_stat():
    ograc_log = setup('ograc')
    if(os.getuid() == 0):
        ograc_log.error("Cannot use root user for this operation!")
        sys.exit(1)
    (result_json) = fetch_cms_version(ograc_log)
    return json.dumps(result_json, indent=1)


if __name__ == '__main__':
    print(fetch_cls_stat())
