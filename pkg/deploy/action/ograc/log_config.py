#!/usr/bin/env python3
"""oGRAC log configuration."""

import logging
from logging import handlers

from config import cfg


def get_logger(name="ograc"):
    log = logging.getLogger(name)
    if log.handlers:
        return log

    fmt = logging.Formatter(
        fmt="%(asctime)s %(levelname)s [pid:%(process)d] [%(threadName)s]"
            " [tid:%(thread)d] [%(filename)s:%(lineno)d %(funcName)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(fmt)
    log.addHandler(console)

    try:
        import os
        log_file = cfg.paths.log_file
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.isdir(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        file_handler = handlers.RotatingFileHandler(
            log_file, maxBytes=20 * 1024 * 1024, backupCount=10,
        )
        file_handler.setFormatter(fmt)
        log.addHandler(file_handler)
    except (PermissionError, OSError):
        pass

    log.setLevel(logging.INFO)
    return log

