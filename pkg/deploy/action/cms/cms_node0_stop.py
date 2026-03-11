"""
CMS Node0 停止脚本（重构版）

重构要点:
  - 使用 config.py 统一配置（路径解耦）
  - 使用 utils.py 公共工具（代码复用，替代独立的 _exec_popen）
  - 更清晰的错误处理
"""

import os
import sys
import subprocess

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
if CUR_DIR not in sys.path:
    sys.path.insert(0, CUR_DIR)

from config import cfg, get_config
from log_config import get_logger
from utils import exec_popen

LOGGER = get_logger()


def stop_services():
    """停止 Node0 CMS 服务"""
    _cfg = get_config()
    cms_enable_flag = _cfg.paths.cms_enable_flag

    LOGGER.info("Stopping node0 CMS services...")

    ret, _, stderr = exec_popen(f"rm -rf {cms_enable_flag}")
    if ret != 0:
        LOGGER.error(f"Error removing cms_enable: {stderr}")

    ret, _, stderr = exec_popen("kill -9 $(pidof cms)")
    if ret != 0:
        LOGGER.error(f"Error stopping CMS process: {stderr}")


def ping_kubernetes_service():
    """检查 Kubernetes 服务是否可达"""
    try:
        subprocess.check_output(
            ["timeout", "1", "ping", "-c", "1", "kubernetes.default.svc"],
            stderr=subprocess.STDOUT,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def main():
    _cfg = get_config()
    node_id = _cfg.deploy.node_id
    ograc_in_container = _cfg.deploy.ograc_in_container

    if str(node_id) == "0" and ograc_in_container in ("1", "2"):
        if not ping_kubernetes_service():
            LOGGER.info("Kubernetes service is not reachable. Stopping CMS services...")
            stop_services()


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        LOGGER.error(f"Error: {err}")
