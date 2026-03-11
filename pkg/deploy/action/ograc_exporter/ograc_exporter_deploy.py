"""
ograc_exporter 部署编排器（root 身份运行）

按 REFACTOR_SPEC 要求，把原 appctl.sh + pre_install.sh 中的 root 级
shell 逻辑全部 Python 化。

职责：
  - 权限管理：文件属主 / 目录权限
  - 日志目录准备
  - 文件拷贝（非 RPM 场景）
  - 通过 run_python_as_user 调用 ograc_exporter_ctl.py 执行业务动作
"""

import os
import shutil
import sys

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
if CUR_DIR not in sys.path:
    sys.path.insert(0, CUR_DIR)

from config import get_config
from log_config import get_logger
from utils import (
    CommandError, ensure_dir, ensure_file,
    run_python_as_user, exec_popen, chown_recursive, chmod_recursive,
)

LOG = get_logger()


class ExporterDeploy:
    def __init__(self):
        self._cfg = get_config()
        self.paths = self._cfg.paths
        self.timeout = self._cfg.timeout
        self.user = self._cfg.user
        self.group = self._cfg.group
        self.common_group = self._cfg.common_group
        self.user_group = f"{self.user}:{self.group}"
        self.user_cgroup = f"{self.user}:{self.common_group}"

    def _mod_prepare(self, action_type=""):
        """原 pre_install.sh 全部 Python 化"""
        p = self.paths

        ctl_dir = CUR_DIR
        user_files = [
            "ograc_exporter_ctl.py", "config.py", "log_config.py", "utils.py",
        ]
        for fname in user_files:
            fpath = os.path.join(ctl_dir, fname)
            if os.path.isfile(fpath):
                exec_popen(f'chown -h {self.user_group} "{fpath}"')

        if not os.path.isfile(p.rpm_flag):
            exec_popen(f'chmod 755 "{ctl_dir}"')
            exec_popen(f'chmod 400 "{ctl_dir}"/*')

        if action_type != "rollback" and not os.path.isfile(p.rpm_flag):
            dst = p.action_dir
            if os.path.realpath(ctl_dir) != os.path.realpath(dst):
                action_parent = os.path.dirname(dst)
                if os.path.isdir(action_parent):
                    if os.path.isdir(dst):
                        shutil.rmtree(dst)
                    shutil.copytree(ctl_dir, dst)
                    LOG.info(f"Copied action scripts to {dst}")

        for d in [p.og_om_dir, p.og_om_service_dir]:
            if os.path.isdir(d):
                exec_popen(f'chown -h {self.user_cgroup} "{d}"')
        if os.path.isdir(p.service_base):
            chown_recursive(p.service_base, self.user_cgroup)

        ensure_dir(p.log_dir, 0o750)
        ensure_file(p.log_file, 0o640)

        if os.path.isdir(p.deploy_logs_dir):
            exec_popen(f'chmod 755 "{p.deploy_logs_dir}"')

        if os.path.isdir(p.log_dir):
            chmod_recursive(p.log_dir, "740")
            if os.path.isfile(p.log_file):
                os.chmod(p.log_file, 0o640)
            chown_recursive(p.log_dir, self.user_group)

        LOG.info("mod_prepare done")

    def _run_ctl(self, action):
        script = os.path.join(CUR_DIR, "ograc_exporter_ctl.py")
        op_timeout = self.timeout.get(action)
        rc, out, err = run_python_as_user(
            script, [action], self.user,
            log_file=self.paths.log_file, timeout=op_timeout,
        )
        if rc != 0:
            raise CommandError(f"ograc_exporter_ctl.py {action}", rc, out, err)
        for part in (out, err):
            if not part:
                continue
            for line in part.splitlines():
                if line.strip():
                    LOG.info(line)

    def action_start(self):
        """原 appctl.sh start 逻辑"""
        p = self.paths
        if os.path.isdir(p.data_dir):
            chown_recursive(p.data_dir, self.user_cgroup)
        self._run_ctl("start")

    def action_stop(self):
        self._run_ctl("stop")

    def action_check_status(self):
        self._run_ctl("check_status")

    def action_install(self):
        """原 appctl.sh install 逻辑"""
        self._mod_prepare()

    def action_uninstall(self):
        """no-op，与原脚本一致"""
        LOG.info("uninstall: no-op")

    def action_upgrade(self):
        self._mod_prepare()

    def action_rollback(self):
        self._mod_prepare(action_type="rollback")

    def action_pre_install(self):
        LOG.info("pre_install: no-op")

    def action_backup(self):
        LOG.info("backup: no-op")

    def action_restore(self):
        LOG.info("restore: no-op")

    def action_pre_upgrade(self):
        LOG.info("pre_upgrade: no-op")

    def action_upgrade_backup(self):
        LOG.info("upgrade_backup: no-op")

    def action_post_upgrade(self):
        LOG.info("post_upgrade: no-op")



def main():
    if len(sys.argv) < 2:
        print("Usage: python3 ograc_exporter_deploy.py <action>", file=sys.stderr)
        sys.exit(1)

    action = sys.argv[1]
    deployer = ExporterDeploy()

    action_map = {
        "start": deployer.action_start,
        "stop": deployer.action_stop,
        "check_status": deployer.action_check_status,
        "install": deployer.action_install,
        "uninstall": deployer.action_uninstall,
        "pre_install": deployer.action_pre_install,
        "backup": deployer.action_backup,
        "restore": deployer.action_restore,
        "pre_upgrade": deployer.action_pre_upgrade,
        "upgrade_backup": deployer.action_upgrade_backup,
        "upgrade": deployer.action_upgrade,
        "post_upgrade": deployer.action_post_upgrade,
        "rollback": deployer.action_rollback,
    }

    fn = action_map.get(action)
    if fn is None:
        print(f"Unknown action: {action}", file=sys.stderr)
        sys.exit(1)

    try:
        fn()
    except CommandError as e:
        details = "\n".join(part for part in (e.stdout.strip(), e.stderr.strip()) if part)
        if details:
            LOG.error("%s\n%s", str(e), details)
        else:
            LOG.error(str(e))
        sys.exit(1)
    except Exception as e:
        LOG.error(str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
