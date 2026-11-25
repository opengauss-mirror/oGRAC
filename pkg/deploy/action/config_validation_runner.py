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

"""Shared config_params_lun.json validation entry points."""

import os

from config_param_validator import ConfigParamValidationError, validate_config_params_file


def resolve_config_params_file(action_root, config_file=""):
    """Resolve config_params_lun.json path from root or caller-provided path."""
    if not config_file:
        return os.path.join(action_root, "config_params_lun.json")
    if os.path.isabs(config_file):
        return config_file
    cwd_path = os.path.abspath(config_file)
    if os.path.exists(cwd_path):
        return cwd_path
    return os.path.join(action_root, config_file)


def validate_config_params_or_raise(action_root, config_file="", logger=None):
    """Validate config params with a consistent error mode for deploy modules."""
    resolved = resolve_config_params_file(action_root, config_file)
    try:
        validate_config_params_file(resolved, logger=logger)
    except ConfigParamValidationError as error:
        raise RuntimeError(f"config validation failed: {error}") from error
    return resolved
