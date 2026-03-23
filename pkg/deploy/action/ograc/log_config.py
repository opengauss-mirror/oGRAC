#!/usr/bin/env python3
"""oGRAC log configuration."""

import logging
from logging import handlers

from config import cfg


def get_logger(name="ograc"):
    log = logging.getLogger(name)
    if log.handlers:
        return log

    console = logging.StreamHandler()
    console.setLevel(logging.INFO)

    file_handler = handlers.RotatingFileHandler(
        cfg.paths.log_file, maxBytes=20 * 1024 * 1024, backupCount=10,
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

