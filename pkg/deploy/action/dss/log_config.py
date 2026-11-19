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

"""DSS log configuration module."""

import logging
from logging import handlers
from config import cfg


def get_logger(name="dss"):
    """Get DSS logger instance."""
    log = logging.getLogger(name)
    if log.handlers:
        return log

    log_file = cfg.paths.dss_deploy_log

    console = logging.StreamHandler()
    console.setLevel(logging.INFO)

    file_handler = handlers.RotatingFileHandler(
        log_file, maxBytes=6291456, backupCount=5,
    )

    fmt = logging.Formatter(
        fmt="%(asctime)s %(levelname)s [pid:%(process)d] [%(threadName)s]"
            " [tid:%(thread)d] [%(filename)s:%(lineno)d %(funcName)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console.setFormatter(fmt)
    file_handler.setFormatter(fmt)
    log.addHandler(console)
    log.addHandler(file_handler)
    log.setLevel(logging.INFO)

    return log
