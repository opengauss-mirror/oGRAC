#!/usr/bin/env python3
"""utils unified configuration module."""

import os
import sys

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
PKG_DIR = os.path.abspath(os.path.join(CUR_DIR, "../.."))


class PathConfig:
    def __init__(self, ograc_home="/opt/ograc"):
        self.ograc_home = ograc_home


class UtilsConfig:
    def __init__(self):
        ograc_home = os.environ.get("OGRAC_HOME", "/opt/ograc")
        self.paths = PathConfig(ograc_home=ograc_home)


_global_cfg = None


def get_config():
    global _global_cfg
    if _global_cfg is None:
        _global_cfg = UtilsConfig()
    return _global_cfg


class _LazyCfg:
    def __getattr__(self, name):
        return getattr(get_config(), name)


cfg = _LazyCfg()
