#!/usr/bin/env python3
"""logicrep log configuration."""

import logging
import os
from logging import handlers

from config import cfg


def get_logger(name="logicrep"):
    log = logging.getLogger(name)
    if log.handlers:
        return log

    console = logging.StreamHandler()
    console.setLevel(logging.INFO)

    log_file = cfg.paths.log_file
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    file_handler = handlers.RotatingFileHandler(
        log_file, maxBytes=6 * 1024 * 1024, backupCount=5,
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
