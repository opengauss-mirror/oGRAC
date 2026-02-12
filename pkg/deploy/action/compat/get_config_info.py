"""
向后兼容入口 —— 所有逻辑已迁移至 config.py

保留此文件仅为兼容 shell 脚本中 `python3 get_config_info.py <param>` 的调用方式。
新代码请直接使用:
    from config import cfg
    value = cfg.get("param_name")
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import get_value, get_config


def get_env_info(key):
    deploy = get_config().deploy
    env_map = {
        "ograc_user": deploy.ograc_user,
        "ograc_group": deploy.ograc_group,
        "ograc_common_group": deploy.ograc_common_group,
    }
    return env_map.get(key, "")


if __name__ == "__main__":
    _param = sys.argv[1]
    print(get_value(_param))
