#!/usr/bin/env python3
"""ograc_exporter log configuration."""

import logging
import os
from logging import handlers

from config import cfg


def get_logger(name="ograc_exporter"):
    log = logging.getLogger(name)
    if log.handlers:
        return log

    console = logging.StreamHandler()
    console.setLevel(logging.INFO)

    log_file = cfg.paths.log_file
    try:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
    except OSError:
        pass

    fmt = logging.Formatter(
        fmt="%(asctime)s %(levelname)s [pid:%(process)d] [%(filename)s:%(lineno)d %(funcName)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    console.setFormatter(fmt)

    log.addHandler(console)
    try:
        file_handler = handlers.RotatingFileHandler(
            log_file, maxBytes=10 * 1024 * 1024, backupCount=5,
        )
        file_handler.setFormatter(fmt)
        log.addHandler(file_handler)
    except (PermissionError, OSError) as e:
        log.warning("Cannot open log file %s (%s), logging to console only", log_file, e)
    log.setLevel(logging.INFO)
    return log
