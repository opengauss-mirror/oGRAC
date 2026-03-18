#!/usr/bin/env python3
"""oGRAC upgrade/rollback orchestrator."""

import os
import sys
import glob
import time

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
ACTION_DIR = os.path.dirname(CUR_DIR)
sys.path.insert(0, ACTION_DIR)

from config import get_config, reset_config
from log_config import get_logger
from utils import (
    exec_popen, run_cmd, run_as_user, ensure_dir, safe_remove,
    copy_tree, read_version, chown_recursive, CommandError,
    is_process_running, kill_process, read_json, write_json,
)

LOG = get_logger("deploy")

UPGRADE_ORDER = ["og_om", "ograc_exporter", "cms", "ograc"]
ROLLBACK_ORDER = ["cms", "ograc", "og_om", "ograc_exporter"]
POST_UPGRADE_ORDER = ["og_om", "ograc_exporter", "cms", "ograc"]
PRE_UPGRADE_ORDER = ["og_om", "ograc_exporter", "cms", "ograc"]


class OgracUpgrade:
    def __init__(self):
        self.cfg = get_config()
        self.paths = self.cfg.paths
        self.deploy = self.cfg.deploy
        self.ograc_user = self.deploy.ograc_user
        self.ograc_group = self.deploy.ograc_group
        self.deploy_mode = self.deploy.deploy_mode
        self.node_id = self.deploy.node_id
        self.ograc_in_container = self.deploy.ograc_in_container
        self.storage_metadata_fs = self.deploy.storage_metadata_fs

    def _call_module(self, module, action, *extra_args):
        appctl = os.path.join(self.paths.action_dir, module, "appctl.sh")
        if not os.path.exists(appctl):
            appctl = os.path.join(ACTION_DIR, module, "appctl.sh")
        if not os.path.exists(appctl):
            LOG.warning("Module %s appctl.sh not found", module)
            return 0
        cmd = f"sh {appctl} {action}"
        if extra_args:
            cmd += " " + " ".join(str(a) for a in extra_args)
        ret, stdout, stderr = exec_popen(cmd, timeout=self.cfg.timeout(action) or 3600)
        if ret != 0:
            LOG.error("%s %s failed: %s", module, action, stderr)
        return ret

    def _get_source_version(self):
        script = os.path.join(ACTION_DIR, "implement", "get_source_version.py")
        ret, stdout, _ = exec_popen(f"python3 {script}")
        return stdout.strip() if ret == 0 else ""

    def _get_target_version(self):
        versions_file = os.path.join(os.path.dirname(ACTION_DIR), "versions.yml")
        return read_version(versions_file)

    def pre_upgrade(self, upgrade_mode="offline", config_file=""):
        LOG.info("Begin pre_upgrade, mode=%s", upgrade_mode)

        if config_file and os.path.exists(config_file):
            pre_upgrade_py = os.path.join(CUR_DIR, "pre_upgrade.py")
            ret, _, stderr = exec_popen(
                f"python3 {pre_upgrade_py} {config_file}",
                timeout=self.cfg.timeout("pre_upgrade"))
            if ret != 0:
                LOG.error("pre_upgrade config check failed: %s", stderr)
                return 1
            config_dir = os.path.join(os.path.dirname(ACTION_DIR), "config")
            deploy_param_src = os.path.join(ACTION_DIR, "deploy_param.json")
            if os.path.exists(deploy_param_src):
                os.rename(deploy_param_src,
                          os.path.join(config_dir, "deploy_param.json"))

        self._check_upgrade_version(upgrade_mode)

        for module in PRE_UPGRADE_ORDER:
            ret = self._call_module(module, "pre_upgrade")
            if ret != 0:
                LOG.error("pre_upgrade %s failed", module)
                return 1

        self._gen_upgrade_plan(upgrade_mode)
        LOG.info("pre_upgrade completed successfully")
        return 0

    def upgrade(self, upgrade_mode="offline", dorado_ip=""):
        LOG.info("Begin upgrade, mode=%s", upgrade_mode)

        source_version = self._get_source_version()
        if not source_version:
            LOG.error("Failed to get source version")
            return 1

        self._check_ograc_stopped()

        backup_path = self.paths.upgrade_backup_path(source_version)
        self._do_backup(backup_path)
        self._do_upgrade(backup_path)
        self._start_ograc()
        self._check_local_nodes()

        if self.node_id == "0":
            self._modify_sys_tables(backup_path, source_version)

        LOG.info("upgrade completed successfully")
        return 0

    def rollback(self, rollback_mode="offline", dorado_ip="",
                 rollback_version=""):
        LOG.info("Begin rollback, mode=%s", rollback_mode)

        back_version = rollback_version or self._get_backup_version()
        if not back_version:
            LOG.error("Failed to get rollback version")
            return 1

        backup_path = self.paths.upgrade_backup_path(back_version)
        if not os.path.exists(os.path.join(backup_path, "backup_success")):
            LOG.error("Backup for version %s not complete", back_version)
            return 1

        self._check_ograc_stopped()
        self._do_rollback(backup_path, back_version)
        self._start_ograc()
        self._check_local_nodes()
        self._clear_tag_files(back_version, rollback_mode)

        LOG.info("rollback completed successfully")
        return 0

    def upgrade_commit(self, upgrade_mode="offline"):
        LOG.info("Begin upgrade_commit, mode=%s", upgrade_mode)

        source_version = self._get_source_version()
        commit_flag = self._get_commit_flag(source_version, upgrade_mode)

        if os.path.exists(commit_flag):
            LOG.info("Upgrade commit already done")
            return 0

        self._raise_version_num()

        open(commit_flag, 'a').close()
        os.chmod(commit_flag, 0o600)

        self._clear_upgrade_residual(source_version, upgrade_mode)
        LOG.info("upgrade_commit completed successfully")
        return 0

    def check_point(self):
        LOG.info("Begin check_point")
        check_point_file = os.path.join(
            self.paths.action_dir, "ograc", "upgrade_checkpoint.sh")
        check_point_flag = os.path.join(
            self.paths.ograc_home, "check_point.success")

        safe_remove(check_point_flag)

        ret, _, stderr = run_as_user(
            f"sh {check_point_file} 127.0.0.1", self.ograc_user,
            timeout=self.cfg.timeout("default"))
        if ret != 0:
            LOG.error("check_point failed: %s", stderr)
            return 1

        open(check_point_flag, 'a').close()
        os.chmod(check_point_flag, 0o400)
        LOG.info("check_point success")
        return 0


    def _check_upgrade_version(self, upgrade_mode):
        LOG.info("Checking upgrade version whitelist")
        script = os.path.join(ACTION_DIR, "implement", "upgrade_version_check.py")
        whitelist = os.path.join(CUR_DIR, "white_list.txt")
        ret, stdout, _ = exec_popen(
            f"python3 {script} {whitelist} {upgrade_mode}")
        if ret != 0 or not stdout.strip():
            LOG.error("Whitelist check failed")
            raise CommandError("Upgrade version check failed")
        LOG.info("Whitelist check passed: %s", stdout.strip())

    def _gen_upgrade_plan(self, upgrade_mode):
        LOG.info("Generating upgrade plan")
        if not self.storage_metadata_fs:
            return
        upgrade_path = os.path.join(
            self.paths.metadata_path(self.storage_metadata_fs), "upgrade")
        ensure_dir(upgrade_path, mode=0o755)

    def _check_ograc_stopped(self):
        LOG.info("Checking oGRAC is stopped")
        for proc in ("ogracd", "cms server.*start", "ograc_daemon.sh"):
            if is_process_running(proc):
                LOG.error("Process %s is still running", proc)
                raise CommandError(f"Process {proc} still running")

    def _do_backup(self, backup_path):
        LOG.info("Backing up to %s", backup_path)
        if os.path.exists(os.path.join(backup_path, "backup_success")):
            LOG.info("Backup already exists")
            return

        ensure_dir(backup_path, mode=0o755)

        for src_dir in ("action", "repo", "common", "config"):
            src = os.path.join(self.paths.ograc_home, src_dir)
            if os.path.isdir(src):
                copy_tree(src, os.path.join(backup_path, src_dir))

        versions_src = self.paths.versions_yml
        if os.path.exists(versions_src):
            import shutil
            shutil.copy2(versions_src, backup_path)

        for module in UPGRADE_ORDER:
            self._call_module(module, "upgrade_backup", backup_path)

        open(os.path.join(backup_path, "backup_success"), 'a').close()
        os.chmod(os.path.join(backup_path, "backup_success"), 0o400)

    def _do_upgrade(self, backup_path):
        LOG.info("Performing upgrade")

        self._copy_new_resources()
        self._reinstall_ograc_package()

        for module in UPGRADE_ORDER:
            ret = self._call_module(module, "upgrade", "offline", backup_path)
            if ret != 0:
                LOG.error("Upgrade %s failed", module)
                raise CommandError(f"Upgrade {module} failed")

        self._update_config_after_upgrade()

    def _do_rollback(self, backup_path, back_version):
        LOG.info("Performing rollback to %s", back_version)

        self._reinstall_ograc_package_from_backup(backup_path)

        for module in ROLLBACK_ORDER:
            ret = self._call_module(module, "rollback", "offline", backup_path)
            if ret != 0:
                LOG.error("Rollback %s failed", module)
                raise CommandError(f"Rollback {module} failed")

        for src_dir in ("action", "common", "config", "repo"):
            src = os.path.join(backup_path, src_dir)
            dst = os.path.join(self.paths.ograc_home, src_dir)
            if os.path.isdir(src):
                copy_tree(src, dst)

        versions_src = os.path.join(backup_path, "versions.yml")
        if os.path.exists(versions_src):
            import shutil
            shutil.copy2(versions_src, self.paths.ograc_home)

    def _copy_new_resources(self):
        LOG.info("Copying new resources for upgrade")
        safe_remove("/etc/systemd/system/ograc*.service")
        safe_remove("/etc/systemd/system/ograc*.timer")

        from ograc_deploy import OgracDeploy
        OgracDeploy()._install_systemd_units()

        pkg_dir = os.path.dirname(ACTION_DIR)
        action_dst = self.paths.action_dir
        for item in ("inspection", "implement", "logic", "storage_operate",
                      "ograc_common", "docker", "utils", "upgrade", "compat"):
            src = os.path.join(ACTION_DIR, item)
            if os.path.isdir(src):
                copy_tree(src, os.path.join(action_dst, item))

        for item in ("config", "common"):
            src = os.path.join(pkg_dir, item)
            dst = os.path.join(self.paths.ograc_home, item)
            if os.path.isdir(src):
                copy_tree(src, dst)

        repo_dst = os.path.join(self.paths.ograc_home, "repo")
        safe_remove(os.path.join(repo_dst, "*"))
        repo_src = os.path.join(pkg_dir, "repo")
        if os.path.isdir(repo_src):
            copy_tree(repo_src, repo_dst)

    def _reinstall_ograc_package(self):
        LOG.info("Reinstalling oGRAC package")
        install_base = os.path.join(self.paths.ograc_home, "image")
        safe_remove(install_base)

        tar_files = glob.glob(
            os.path.join(os.path.dirname(ACTION_DIR), "repo", "ograc-*.tar.gz"))
        if not tar_files:
            LOG.error("oGRAC tar.gz not found")
            raise CommandError("oGRAC package not found")

        ensure_dir(install_base, mode=0o755)
        exec_popen(f"tar -zxf {tar_files[0]} -C {install_base}")
        exec_popen(f"chmod +x -R {install_base}")

        unpack_path = os.path.join(
            install_base, "ograc_connector", "ogracKernel",
            "oGRAC-DATABASE-LINUX-64bit", "oGRAC-RUN-LINUX-64bit.tar.gz")
        if os.path.exists(unpack_path):
            exec_popen(f"tar -zxf {unpack_path} -C {install_base}")

        rpm_path = os.path.join(install_base, "oGRAC-RUN-LINUX-64bit")
        if os.path.isdir(rpm_path):
            exec_popen(f"chmod -R 750 {rpm_path}")
            exec_popen(
                f"chown {self.ograc_user}:{self.ograc_group} -hR {rpm_path}")
            exec_popen(f"chown root:root {install_base}")

    def _reinstall_ograc_package_from_backup(self, backup_path):
        LOG.info("Reinstalling oGRAC package from backup")
        install_base = os.path.join(self.paths.ograc_home, "image")
        safe_remove(install_base)

        tar_files = glob.glob(os.path.join(backup_path, "repo", "ograc-*.tar.gz"))
        if not tar_files:
            LOG.error("Backup oGRAC tar.gz not found")
            raise CommandError("Backup oGRAC package not found")

        ensure_dir(install_base, mode=0o755)
        exec_popen(f"tar -zxf {tar_files[0]} -C {install_base}")
        exec_popen(f"chmod +x -R {install_base}")

        unpack_path = os.path.join(
            install_base, "ograc_connector", "ogracKernel",
            "oGRAC-DATABASE-LINUX-64bit", "oGRAC-RUN-LINUX-64bit.tar.gz")
        if os.path.exists(unpack_path):
            exec_popen(f"tar -zxf {unpack_path} -C {install_base}")

        rpm_path = os.path.join(install_base, "oGRAC-RUN-LINUX-64bit")
        if os.path.isdir(rpm_path):
            exec_popen(f"chmod -R 750 {rpm_path}")
            exec_popen(f"chown {self.ograc_user}:{self.ograc_group} -hR {rpm_path}")
            exec_popen(f"chown root:root {install_base}")

    def _update_config_after_upgrade(self):
        LOG.info("Updating config after upgrade")
        update_script = os.path.join(ACTION_DIR, "compat", "update_config.py")
        configs = [
            ("cms_ini", "add", "CMS_LOG", "/opt/ograc/log/cms"),
            ("ograc_ini", "update", "LOG_HOME", "/opt/ograc/log/ograc"),
            ("ograc_ini", "add", "MES_SSL_SWITCH", "FALSE"),
            ("cms_ini", "add", "_CMS_MES_SSL_SWITCH", "False"),
            ("ograc_ini", "add", "MES_SSL_CRT_KEY_PATH",
             "/opt/ograc/common/config/certificates"),
            ("cms_ini", "add", "_CMS_MES_SSL_CRT_KEY_PATH",
             "/opt/ograc/common/config/certificates"),
        ]
        for comp, action, key, value in configs:
            run_as_user(
                f"python3 -B {update_script} --component={comp} "
                f"--action={action} --key={key} --value={value}",
                self.ograc_user)

    def _start_ograc(self):
        LOG.info("Starting oGRAC after upgrade/rollback")
        from ograc_deploy import OgracDeploy
        deployer = OgracDeploy()
        ret = deployer.start()
        if ret != 0:
            LOG.error("Start oGRAC failed")
            deployer.stop()
            raise CommandError("Start oGRAC after upgrade failed")

    def _check_local_nodes(self):
        LOG.info("Post-upgrade local node check")
        fetch_stat = os.path.join(CUR_DIR, "fetch_cls_stat.py")
        ret, stdout, _ = exec_popen(f"python3 {fetch_stat}")
        if ret != 0 or (stdout and stdout.strip()[-1] != "0"):
            LOG.error("CMS stat check failed")
            raise CommandError("CMS stat check failed after upgrade")

        for module in POST_UPGRADE_ORDER:
            self._call_module(module, "post_upgrade")

    def _modify_sys_tables(self, backup_path, source_version):
        LOG.info("Checking if system tables need modification")
        upgrade_path = ""
        if self.storage_metadata_fs:
            upgrade_path = os.path.join(
                self.paths.metadata_path(self.storage_metadata_fs), "upgrade")

        flag_file = os.path.join(upgrade_path, "updatesys.true") if upgrade_path else ""
        success_file = os.path.join(upgrade_path, "updatesys.success") if upgrade_path else ""

        if not flag_file or not os.path.exists(flag_file):
            LOG.info("No system table modification needed")
            return
        if success_file and os.path.exists(success_file):
            LOG.info("System tables already modified")
            return

        LOG.info("System table modification would be performed here")

    def _raise_version_num(self):
        LOG.info("Raising version number via CMS tool")
        target_version = self._get_target_version()
        if not target_version:
            LOG.warning("Cannot determine target version")
            return

        import re
        match = re.match(r'(\d+\.\d+(?:\.\d+)?)', target_version)
        if not match:
            return
        version_nums = match.group(1)
        format_target = version_nums.replace(".", " ") + " 0"

        for i in range(10):
            ret, _, _ = run_as_user(
                f"source ~/.bashrc && cms upgrade -version {format_target}",
                self.ograc_user)
            if ret == 0:
                LOG.info("Version raise success")
                return
            time.sleep(10)
        LOG.error("Failed to raise version after 10 attempts")

    def _get_backup_version(self):
        backup_note = "/opt/backup_note"
        if not os.path.exists(backup_note):
            return ""
        with open(backup_note, "r") as f:
            lines = f.readlines()
        if not lines:
            return ""
        last_line = lines[-1].strip()
        return last_line.split(":")[0] if ":" in last_line else last_line

    def _get_commit_flag(self, source_version, upgrade_mode):
        if not self.storage_metadata_fs:
            return os.path.join(self.paths.ograc_home,
                                f"ograc_{upgrade_mode}_commit_{source_version}.success")
        return os.path.join(
            self.paths.metadata_path(self.storage_metadata_fs),
            "upgrade",
            f"ograc_{upgrade_mode}_upgrade_commit_{source_version}.success")

    def _clear_tag_files(self, back_version, rollback_mode):
        LOG.info("Clearing tag files")
        check_point_flag = os.path.join(
            self.paths.ograc_home, "check_point.success")
        upgrade_flag = os.path.join(
            self.paths.ograc_home, f"pre_upgrade_{rollback_mode}.success")
        for f in (check_point_flag, upgrade_flag):
            safe_remove(f)

    def _clear_upgrade_residual(self, source_version, upgrade_mode):
        LOG.info("Clearing upgrade residual data")
        pre_flag = os.path.join(
            self.paths.ograc_home, f"pre_upgrade_{upgrade_mode}.success")
        safe_remove(pre_flag)

        if self.storage_metadata_fs:
            upgrade_path = os.path.join(
                self.paths.metadata_path(self.storage_metadata_fs), "upgrade")
            status_path = os.path.join(upgrade_path, "cluster_and_node_status")
            safe_remove(status_path)
            for pattern in ("call_ctback_tool.success", "updatesys.*"):
                for f in glob.glob(os.path.join(upgrade_path, pattern)):
                    safe_remove(f)


def main():
    if len(sys.argv) < 2:
        print("Usage: ograc_upgrade.py <action> [args...]")
        sys.exit(1)

    action = sys.argv[1]
    args = sys.argv[2:]

    upgrader = OgracUpgrade()

    action_map = {
        "pre_upgrade": lambda: upgrader.pre_upgrade(
            args[0] if args else "offline",
            args[1] if len(args) > 1 else ""),
        "upgrade": lambda: upgrader.upgrade(
            args[0] if args else "offline",
            args[1] if len(args) > 1 else ""),
        "rollback": lambda: upgrader.rollback(
            args[0] if args else "offline",
            args[1] if len(args) > 1 else "",
            args[2] if len(args) > 2 else ""),
        "upgrade_commit": lambda: upgrader.upgrade_commit(
            args[0] if args else "offline"),
        "check_point": lambda: upgrader.check_point(),
    }

    handler = action_map.get(action)
    if handler is None:
        print(f"Unknown upgrade action: {action}")
        sys.exit(1)

    try:
        ret = handler()
        sys.exit(ret or 0)
    except Exception as e:
        LOG.error("Upgrade action %s failed: %s", action, str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
