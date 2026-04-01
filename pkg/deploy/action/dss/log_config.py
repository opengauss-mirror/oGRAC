#!/usr/bin/env python3
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
