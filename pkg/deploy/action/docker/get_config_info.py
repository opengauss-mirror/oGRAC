"""
get_config_info.py (refactored)

Drop-in replacement that delegates to config.DockerConfig.
"""
import sys
import os

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, CUR_DIR)

from config import get_value


if __name__ == "__main__":
    _param = sys.argv[1] if len(sys.argv) > 1 else ""
    res = get_value(_param)
    print(res)
