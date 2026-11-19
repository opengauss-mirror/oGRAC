# Copyright (c) 2026 Huawei Technologies Co., Ltd.
# oGRAC is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

# -*-coding:utf-8-*-

import logging
import os
from logging import handlers
from pathlib import Path
from config.config import CONSOLE_CONF


log_config = CONSOLE_CONF.get("log")


def _get_log_file_path(project):
    logger_file = log_config.get("log_file")
    logger_dir = log_config.get("log_dir")
    res_dir = None

    if logger_file:
        if not logger_dir:
            return logger_file
        else:
            res_dir = os.path.join(logger_dir, logger_file)
            return res_dir

    if logger_dir:
        if not os.path.exists(logger_dir):
            os.makedirs(logger_dir)
        os.chmod(logger_dir, mode=0o750)
        res_dir = os.path.join(logger_dir, f"{project}.log")
        return res_dir

    return res_dir


def setup(project_name):
    """
    init log config
    :param project_name:
    """
    log_root = logging.getLogger()
    for handler in list(log_root.handlers):
        log_root.removeHandler(handler)

    log_path = _get_log_file_path(project_name)
    if log_path:
        file_log = handlers.RotatingFileHandler(
            log_path, maxBytes=log_config.get("log_file_max_size"),
            backupCount=log_config.get("log_file_backup_count"))
        log_root.addHandler(file_log)

    for handler in log_root.handlers:
        handler.setFormatter(
            logging.Formatter(
                fmt=log_config.get("logging_context_format_string"),
                datefmt=log_config.get("log_date_format")))

    if log_config.get("debug"):
        log_root.setLevel(logging.DEBUG)
    else:
        log_root.setLevel(logging.INFO)
    return log_root


EXPORTER_LOG = setup("exporter")
os.chmod(str(Path(log_config.get("log_dir"), "exporter.log")), 0o640)
