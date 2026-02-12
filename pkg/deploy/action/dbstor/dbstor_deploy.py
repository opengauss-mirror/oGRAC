"""
dbstor 部署编排器（root 身份运行）

把原 appctl.sh（584 行 shell）全面 Python 化：
chown_mod_scripts, chown_pre_install_set, chown_install_set,
check_sem_id, safety_upgrade_backup, safety_upgrade,
safety_rollback, record_dbstor_info, check_backup_files 等
"""

import glob
import json
import os
import shutil
import subprocess
import sys

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
if CUR_DIR not in sys.path:
    sys.path.insert(0, CUR_DIR)

from config import get_config
from log_config import get_logger
from utils import (
    CommandError, exec_popen, run_cmd, ensure_dir,
    run_python_as_user, run_shell_as_user, chown_recursive, chmod_recursive,
)

LOG = get_logger()


class DbstorDeploy:
    def __init__(self):
        self._cfg = get_config()
        self.paths = self._cfg.paths
        self.timeout = self._cfg.timeout
        self.user = self._cfg.user
        self.group = self._cfg.group
        self.user_group = f"{self.user}:{self.group}"

        dp = self._cfg.deploy_params
        self.node_id = dp.get("node_id", "")
        self.link_type = dp.get("link_type", "")
        self.in_container = dp.get("ograc_in_container", "0")
        self.deploy_user = dp.get("deploy_user", "")
        self.d_user = self.deploy_user.split(":")[-1] if self.deploy_user else self.user

    def _run_ctl(self, action, extra_args=None):
        script = os.path.join(CUR_DIR, "dbstor_ctl.py")
        args = [f"--act={action}"]
        if extra_args:
            args.extend(extra_args)
        env_extra = {
            "LD_LIBRARY_PATH": f"{self.paths.lib_dir}:{os.environ.get('LD_LIBRARY_PATH', '')}",
        }
        rc, out, err = run_python_as_user(
            script, args, self.user,
            log_file=self.paths.log_file,
            timeout=self.timeout.get(action),
            env_extra=env_extra,
        )
        if rc != 0:
            raise CommandError(f"dbstor_ctl.py {action}", rc, out, err)

    def _chown_mod_scripts(self):
        for f in os.listdir(CUR_DIR):
            fp = os.path.join(CUR_DIR, f)
            if os.path.isfile(fp) and f != "appctl.sh":
                exec_popen(f'chown {self.user_group} "{fp}"')
        os.chmod(CUR_DIR, 0o755)
        for pattern in ("*.sh", "*.py"):
            for fp in glob.glob(os.path.join(CUR_DIR, pattern)):
                os.chmod(fp, 0o400)

    def _chown_pre_install_set(self):
        p = self.paths
        ensure_dir(p.dbstor_scripts, 0o750)
        if os.path.realpath(CUR_DIR) != os.path.realpath(p.dbstor_scripts):
            exec_popen(f'cp -arf "{CUR_DIR}"/* "{p.dbstor_scripts}/"')
        ensure_dir(p.dbstor_home, 0o750)
        ensure_dir(p.log_dir, 0o750)
        if not os.path.isfile(p.log_file):
            open(p.log_file, "a").close()

        for ini in glob.glob(os.path.join(p.backup_files, "*.ini")):
            os.chmod(ini, 0o600)
        for logf in glob.glob(os.path.join(p.log_dir, "*.log")):
            os.chmod(logf, 0o640)

        chown_recursive(p.dbstor_home, self.user_group)
        chown_recursive(p.log_dir, self.user_group)

    def _check_sem_id(self):
        rc, out, _ = exec_popen("lsipc -s -c | grep 0x20161227")
        if out:
            parts = out.split()
            if len(parts) > 1:
                sem_id = parts[1]
                exec_popen(f"ipcrm -s {sem_id}")
                LOG.info(f"Removed semaphore {sem_id}")

    def _chown_install_set(self):
        p = self.paths
        ensure_dir(p.tools_dir, 0o750)
        if os.path.isdir(p.client_test_dir):
            exec_popen(f'cp -rf "{p.client_test_dir}"/* "{p.tools_dir}/"')
            LOG.info("client test copy success.")

        if os.path.isfile(p.dbstor_config_ini):
            os.chmod(p.dbstor_config_ini, 0o640)
        if os.path.isfile(p.client_cfg):
            os.chmod(p.client_cfg, 0o640)

        ensure_dir(p.lib_dir, 0o750)
        if os.path.isdir(p.kmc_shared_dir):
            exec_popen(f'cp -rf "{p.kmc_shared_dir}"/* "{p.lib_dir}/"')
        if os.path.isdir(p.addons_src_dir):
            exec_popen(f'cp -rf "{p.addons_src_dir}" "{p.dbstor_home}/"')

        exec_popen(f'chmod 550 "{p.tools_dir}"/*')
        exec_popen(f'chmod 550 "{p.lib_dir}"/*')
        if os.path.isdir(p.addons_dir):
            exec_popen(f'chmod 550 "{p.addons_dir}"/*')

        for so_name in ("libcrypto.so", "libcrypto.so.1.1", "libkmc.so"):
            so_path = os.path.join(p.lib_dir, so_name)
            if os.path.isfile(so_path):
                os.chmod(so_path, 0o500)

        chown_recursive(p.dbstor_home, self.user_group)

    def _cleanup_shm(self):
        for pattern in self._cfg.shm_cleanup_patterns:
            exec_popen(f"rm -rf {pattern}")

    def _record_dbstor_info(self, backup_dir):
        p = self.paths
        dbstor_bak = os.path.join(backup_dir, "dbstor")
        rc, tree_out, _ = exec_popen(f'tree -afis "{p.dbstor_home}"')
        with open(os.path.join(dbstor_bak, "dbstor_home_files_list.txt"), "w") as f:
            f.write(tree_out)

        import datetime
        with open(os.path.join(dbstor_bak, "backup.bak"), "w") as f:
            f.write("dbstor backup information for upgrade\n")
            f.write(f"time: {datetime.datetime.now()}\n")
            f.write(f"ograc_user: {self.user_group}\n")
            rc2, du_out, _ = exec_popen(f'du -sh "{p.dbstor_home}"')
            f.write(f"dbstor_home: total_size={du_out}\n")

    def _check_backup_files(self, list_file, dest_dir, orig_dir):
        if not os.path.isfile(list_file):
            return
        with open(list_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if "]" in line:
                    size_part = line.split("]")[0].replace("[", "").strip()
                    path_part = line.split("]")[1].strip()
                else:
                    continue
                if not path_part:
                    continue
                if "->" in path_part:
                    path_part = path_part.split("->")[0].strip()
                if not path_part.startswith(orig_dir):
                    continue
                if path_part.startswith(os.path.join(orig_dir, "log")):
                    continue
                dest_path = path_part.replace(orig_dir, dest_dir, 1)
                if not os.path.exists(dest_path):
                    raise RuntimeError(f"Backup verify failed: {path_part} -> {dest_path} not found")

    def _safety_upgrade_backup(self, backup_dir):
        p = self.paths
        LOG.info("begin to backup dbstor module for upgrade")

        old_owner = ""
        rc, out, _ = exec_popen(f'stat -c %U "{p.dbstor_home}"')
        if rc == 0:
            old_owner = out.strip()
        if old_owner and old_owner != self.user:
            raise RuntimeError("the upgrade user is different from the installed user")

        if not backup_dir:
            raise ValueError("backup_dir is empty")

        dbstor_bak = os.path.join(backup_dir, "dbstor")
        if os.path.isdir(dbstor_bak):
            raise RuntimeError(f"{dbstor_bak} already exists, check whether data has been backed up")

        os.makedirs(dbstor_bak, mode=0o750)

        home_bak = os.path.join(dbstor_bak, "dbstor_home")
        os.makedirs(home_bak, mode=0o750)
        for item in os.listdir(p.dbstor_home):
            if item == "log":
                continue
            src = os.path.join(p.dbstor_home, item)
            dst = os.path.join(home_bak, item)
            if os.path.isdir(src):
                shutil.copytree(src, dst)
            else:
                shutil.copy2(src, dst)

        self._record_dbstor_info(backup_dir)
        list_file = os.path.join(dbstor_bak, "dbstor_home_files_list.txt")
        self._check_backup_files(list_file, home_bak, p.dbstor_home)

        self._backup_dbstor_config_ini(backup_dir)
        LOG.info("backup dbstor module for upgrade successfully")

    def _backup_dbstor_config_ini(self, backup_dir):
        p = self.paths
        dbstor_bak = os.path.join(backup_dir, "dbstor")
        for sub in ("conf/ogracd_cnf", "conf/cms_cnf", "conf/share_cnf", "conf/tool_cnf"):
            os.makedirs(os.path.join(dbstor_bak, sub), mode=0o750, exist_ok=True)

        cms_src = os.path.join(p.cms_dbstor_conf, "*")
        ogracd_src = os.path.join(p.local_dbstor_conf, "*")
        tool_src = os.path.join(p.tools_dir, "*")
        exec_popen(f'cp -arf {cms_src} "{os.path.join(dbstor_bak, "conf/cms_cnf")}/"')
        exec_popen(f'cp -arf {ogracd_src} "{os.path.join(dbstor_bak, "conf/ogracd_cnf")}/"')
        exec_popen(f'cp -arf {tool_src} "{os.path.join(dbstor_bak, "conf/tool_cnf")}/"')

        tool_ini = os.path.join(dbstor_bak, "conf", "tool_cnf", "dbstor_config.ini")
        if not os.path.isfile(tool_ini):
            if os.path.isfile(p.dbstor_config_ini):
                shutil.copy2(p.dbstor_config_ini, tool_ini)

    def _safety_upgrade(self, upgrade_path=""):
        p = self.paths
        LOG.info("begin to upgrade dbstor module")

        link_type = self._cfg.get_deploy_param("link_type", "")

        LOG.info(f"update the tools files in {p.tools_dir}")
        exec_popen(f'rm -rf "{p.tools_dir}"/*')
        if os.path.isdir(p.client_test_dir):
            exec_popen(f'cp -arf "{p.client_test_dir}"/* "{p.tools_dir}/"')
        if upgrade_path:
            tool_ini_bak = os.path.join(upgrade_path, "dbstor", "conf", "tool_cnf", "dbstor_config.ini")
            if os.path.isfile(tool_ini_bak):
                shutil.copy2(tool_ini_bak, os.path.join(p.tools_dir, "dbstor_config.ini"))

        LOG.info(f"update the lib files in {p.lib_dir}")
        exec_popen(f'rm -rf "{p.lib_dir}"/*')
        if os.path.isdir(p.kmc_shared_dir):
            exec_popen(f'cp -arf "{p.kmc_shared_dir}"/* "{p.lib_dir}/"')

        config_dir = p.conf_infra_config
        if os.path.isdir(config_dir):
            node_cfg = os.path.join(config_dir, "node_config.xml")
            if os.path.isfile(node_cfg):
                os.remove(node_cfg)
            if link_type in ("1", "2"):
                src = os.path.join(p.cfg_dir, "node_config_rdma.xml")
            else:
                src = os.path.join(p.cfg_dir, "node_config_tcp.xml")
            if os.path.isfile(src):
                shutil.copy2(src, node_cfg)

            osd_cfg = os.path.join(config_dir, "osd.cfg")
            osd_src = os.path.join(p.cfg_dir, "osd.cfg")
            if os.path.isfile(osd_src):
                shutil.copy2(osd_src, osd_cfg)

        chown_recursive(p.dbstor_home, self.user_group)

        LOG.info(f"update the dbstor scripts in {p.dbstor_scripts}")
        if os.path.realpath(CUR_DIR) != os.path.realpath(p.dbstor_scripts):
            if os.path.isdir(p.dbstor_scripts):
                shutil.rmtree(p.dbstor_scripts)
            os.makedirs(p.dbstor_scripts, exist_ok=True)
            exec_popen(f'cp -arf "{CUR_DIR}"/* "{p.dbstor_scripts}/"')
        exec_popen(f'chmod 400 "{p.dbstor_scripts}"/*')
        os.chmod(p.dbstor_scripts, 0o755)
        chown_recursive(p.dbstor_scripts, self.user_group)
        exec_popen(f'chown root:root "{os.path.join(p.dbstor_scripts, "appctl.sh")}"')

        LOG.info("upgrade dbstor module successfully")

    def _safety_rollback(self, rollback_path=""):
        p = self.paths
        LOG.info("begin to rollback dbstor module")

        if not rollback_path:
            raise ValueError("rollback_path is empty")
        ograc_bak = os.path.join(rollback_path, "ograc")
        if not os.path.isdir(ograc_bak):
            raise RuntimeError(f"backup dir {ograc_bak} does not exist")

        dbstor_home_bak = os.path.join(rollback_path, "dbstor", "dbstor_home")
        if not os.path.isdir(dbstor_home_bak):
            raise RuntimeError(f"dir {dbstor_home_bak} does not exist")

        for item in os.listdir(p.dbstor_home):
            if item == "log":
                continue
            fp = os.path.join(p.dbstor_home, item)
            if os.path.isdir(fp):
                shutil.rmtree(fp)
            else:
                os.remove(fp)
        exec_popen(f'cp -arf "{dbstor_home_bak}"/* "{p.dbstor_home}/"')

        list_file = os.path.join(rollback_path, "dbstor", "dbstor_home_files_list.txt")
        self._check_backup_files(list_file, dbstor_home_bak, p.dbstor_home)

        self._rollback_dbstor_config_ini(rollback_path)
        LOG.info("rollback dbstor module successfully")

    def _rollback_dbstor_config_ini(self, rollback_path):
        p = self.paths
        bak_base = os.path.join(rollback_path, "dbstor", "conf")
        cms_bak = os.path.join(bak_base, "cms_cnf")
        ogracd_bak = os.path.join(bak_base, "ogracd_cnf")
        tool_bak = os.path.join(bak_base, "tool_cnf")

        if os.path.isdir(cms_bak):
            exec_popen(f'cp -arf "{cms_bak}"/* "{p.cms_dbstor_conf}/"')
        if os.path.isdir(ogracd_bak):
            exec_popen(f'cp -arf "{ogracd_bak}"/* "{p.local_dbstor_conf}/"')
        if os.path.isdir(tool_bak):
            exec_popen(f'cp -arf "{tool_bak}"/* "{p.tools_dir}/"')

    def action_pre_install(self):
        self._check_sem_id()
        self._chown_mod_scripts()
        self._chown_pre_install_set()

    def action_install(self):
        self._chown_install_set()
        self._run_ctl("install")

    def action_uninstall(self, uninstall_type="", force=""):
        p = self.paths
        if os.path.isfile(p.uninstall_log):
            os.chmod(p.uninstall_log, 0o640)
        self._cleanup_shm()
        extra = []
        if uninstall_type:
            extra.extend([f"--uninstall-type={uninstall_type}"])
        if force:
            extra.extend([f"--force={force}"])
        self._run_ctl("uninstall", extra_args=extra)

    def action_backup(self):
        p = self.paths
        ensure_dir(p.backup_files, 0o750)
        chown_recursive(p.backup_dir, self.user_group)
        self._run_ctl("backup")

    def action_init_container(self):
        self._run_ctl("init_container")

    def action_check_status(self):
        script = os.path.join(os.path.dirname(CUR_DIR), "dbstor", "check_status.sh")
        if os.path.isfile(script):
            rc, out, err = run_shell_as_user(
                f'cd "{os.path.dirname(script)}" && sh "{script}"',
                self.user, timeout=self.timeout.get("check_status"),
            )
            if out:
                LOG.info(out)
            if rc:
                raise CommandError("check_status", rc, out, err)

    def action_pre_upgrade(self):
        LOG.info("dbstor pre_upgrade: no-op")

    def action_upgrade_backup(self, backup_path=""):
        p = self.paths
        version_first = "0"
        if os.path.isfile(p.versions_yml):
            with open(p.versions_yml, encoding="utf-8") as f:
                for line in f:
                    if "Version:" in line:
                        version_first = line.split(":")[1].strip().split(".")[0]
                        break
        self._safety_upgrade_backup(backup_path)

    def action_upgrade(self, upgrade_path=""):
        self._safety_upgrade(upgrade_path)

    def action_rollback(self, rollback_path=""):
        self._safety_rollback(rollback_path)

    def action_post_upgrade(self):
        LOG.info("dbstor post_upgrade: no-op")

    def action_start(self):
        script = os.path.join(os.path.dirname(CUR_DIR), "dbstor", "start.sh")
        if os.path.isfile(script):
            rc, out, err = run_shell_as_user(
                f'cd "{os.path.dirname(script)}" && sh "{script}"',
                self.user, timeout=self.timeout.get("start"),
            )
            if out:
                LOG.info(out)
            if rc:
                raise CommandError("start", rc, out, err)

    def action_stop(self):
        script = os.path.join(os.path.dirname(CUR_DIR), "dbstor", "stop.sh")
        if os.path.isfile(script):
            rc, out, err = run_shell_as_user(
                f'cd "{os.path.dirname(script)}" && sh "{script}"',
                self.user, timeout=self.timeout.get("stop"),
            )
            if out:
                LOG.info(out)
            if rc:
                raise CommandError("stop", rc, out, err)


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 dbstor_deploy.py <action> [args...]", file=sys.stderr)
        sys.exit(1)

    deployer = DbstorDeploy()

    action = sys.argv[1]
    arg2 = sys.argv[2] if len(sys.argv) > 2 else ""
    arg3 = sys.argv[3] if len(sys.argv) > 3 else ""

    action_map = {
        "start": deployer.action_start,
        "stop": deployer.action_stop,
        "pre_install": deployer.action_pre_install,
        "install": deployer.action_install,
        "uninstall": lambda: deployer.action_uninstall(arg2, arg3),
        "check_status": deployer.action_check_status,
        "backup": deployer.action_backup,
        "init_container": deployer.action_init_container,
        "pre_upgrade": deployer.action_pre_upgrade,
        "upgrade_backup": lambda: deployer.action_upgrade_backup(arg2),
        "upgrade": lambda: deployer.action_upgrade(arg3),
        "rollback": lambda: deployer.action_rollback(arg3),
        "post_upgrade": deployer.action_post_upgrade,
    }

    fn = action_map.get(action)
    if fn is None:
        print(f"Unknown action: {action}", file=sys.stderr)
        sys.exit(1)

    try:
        fn()
    except Exception as e:
        LOG.error(str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
