"""DSS 升级提交验证"""

import os
import sys
import traceback

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CUR_DIR)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

from log_config import get_logger
from common.dss_cmd import vg_list_files
from common.file_utils import read_dss_file

LOG = get_logger()

STATUS_VG_PATH = "+vg1/upgrade/cluster_and_node_status"


class DssUpgradeCommit:
    """验证升级提交条件"""

    def __init__(self):
        self.node_status_count = 0

    def _count_status_files(self):
        """统计 status 文件数量"""
        lines = vg_list_files(STATUS_VG_PATH)
        if lines is None:
            raise RuntimeError(f"dsscmd ls {STATUS_VG_PATH} failed")
        if len(lines) == 0:
            raise RuntimeError("cluster_and_node_status is empty")

        for line in lines:
            if "status.txt" in line and "cluster" not in line:
                self.node_status_count += 1

    def _verify_node_count(self, expected_nodes):
        """验证节点 status 文件数量与 CMS 节点数一致"""
        if expected_nodes != self.node_status_count:
            LOG.error(f"Status files: {self.node_status_count}, expected: {expected_nodes}")
            if expected_nodes > self.node_status_count:
                raise RuntimeError("Not enough status files in cluster_and_node_status")
            raise RuntimeError("Too many status files in cluster_and_node_status")

    def _verify_file_contents(self, node_count):
        """验证每个节点的 status 文件内容"""
        for i in range(node_count):
            path = os.path.join(STATUS_VG_PATH, f"node{i}_status.txt")
            content = read_dss_file(path)
            if content != "rollup_success":
                raise RuntimeError(f"Node {i} rollup result error: {content}")

    def commit(self, expected_nodes):
        """执行提交验证"""
        self._count_status_files()
        self._verify_node_count(expected_nodes)
        self._verify_file_contents(expected_nodes)
        LOG.info("Upgrade commit validation passed")


def main():
    if len(sys.argv) < 2:
        raise RuntimeError("Usage: dss_upgrade_commit.py <node_count>")
    try:
        DssUpgradeCommit().commit(int(sys.argv[1]))
    except Exception as e:
        LOG.error(f"Commit check failed: {traceback.format_exc(limit=-1)}")
        raise


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        sys.exit(str(err))
