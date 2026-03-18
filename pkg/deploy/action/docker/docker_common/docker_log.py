#!/usr/bin/env python3
"""Docker logging utilities."""
import os
import sys
import inspect
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from config import get_config

_cfg = get_config()
_paths = _cfg.paths

LOG_PATH = _paths.deploy_log_dir
LOG_FILE = _paths.deploy_log


def init_deploy_logging():
    """Ensure the log directory and file exist."""
    if not os.path.isdir(LOG_PATH):
        os.makedirs(LOG_PATH, exist_ok=True)
    if not os.path.isfile(LOG_FILE):
        with open(LOG_FILE, "a"):
            pass


def _log(level, *args):
    """Write a structured log line to LOG_FILE."""
    frame = inspect.stack()[2]
    caller_file = os.path.basename(frame.filename)
    caller_line = frame.lineno
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S,%f %z").strip()
    pid = os.getpid()
    msg = " ".join(str(a) for a in args)
    line = f"[{now}] [{level}] [{pid:>5d}] [{caller_file}:{caller_line}] {msg}\n"
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line)
    except Exception:
        pass


def log_info(*args):
    _log("INFO", *args)


def log_warn(*args):
    _log("WARN", *args)


def log_error(*args):
    _log("ERROR", *args)


def log_and_echo_info(*args):
    log_info(*args)
    print(f"[INFO ] {' '.join(str(a) for a in args)}")


def log_and_echo_warn(*args):
    log_warn(*args)
    print(f"[WARN ] {' '.join(str(a) for a in args)}")


def log_and_echo_error(*args):
    log_error(*args)
    print(f"[ERROR] {' '.join(str(a) for a in args)}")


init_deploy_logging()
