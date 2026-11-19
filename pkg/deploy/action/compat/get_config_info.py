#!/usr/bin/env python3
# Copyright (c) 2026 Huawei Technologies Co., Ltd.
# oGRAC is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

"""
Backward-compatible entry point -- all logic migrated to config.py.

Kept only for shell scripts calling `python3 get_config_info.py <param>`.
New code should use: from config import cfg; value = cfg.get("param_name")
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import get_value, get_config


def get_env_info(key):
    deploy = get_config().deploy
    env_map = {
        "ograc_user": deploy.ograc_user,
        "ograc_group": deploy.ograc_group,
        "ograc_common_group": deploy.ograc_common_group,
    }
    return env_map.get(key, "")


if __name__ == "__main__":
    _param = sys.argv[1]
    print(get_value(_param))
