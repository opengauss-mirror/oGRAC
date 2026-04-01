#!/usr/bin/env python3
"""logicrep deploy orchestrator (runs as root)."""

import glob
import os
import shutil
import subprocess
import sys
import time

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
if CUR_DIR not in sys.path:
    sys.path.insert(0, CUR_DIR)

from config import get_config
from log_config import get_logger
from utils import (
    CommandError, exec_popen, ensure_dir,
    run_python_as_user, run_shell_as_user, chown_recursive,
)

LOG = get_logger()


class LogicrepDeploy:
    def __init__(self):
        self._cfg = get_config()
        self.paths = self._cfg.paths
        self.timeout = self._cfg.timeout
        self.user = self._cfg.user
        self.group = self._cfg.group
        self.user_group = f"{self.user}:{self.group}"

        dp = self._cfg.deploy_params
        self.deploy_group = dp.get("deploy_group", self.group)
        self.node_id = dp.get("node_id", "")
        self.node_count = dp.get("cluster_scale", "")
        self.in_container = dp.get("ograc_in_container", "0")
        self.storage_archive_fs = dp.get("storage_archive_fs", "")
        self.install_type = dp.get("install_type", "")

        data_root = self.paths.data_root
        self.archive_path = f"{data_root}/remote/archive_{self.storage_archive_fs}"
        self.startup_lock = f"{self.archive_path}/logicre_startup.lock"
        self.startup_status_file = f"{self.archive_path}/logicrep_status"

        pkg_dir = os.path.abspath(os.path.join(CUR_DIR, "../.."))
        self.logicrep_pkg = os.path.join(pkg_dir, "zlogicrep", "build", "oGRAC_PKG", "file")

    def _run_ctl(self, action, mode=""):
        p = self.paths
        script = os.path.join(CUR_DIR, "logicrep_ctl.py")
        args = [f"--act={action}"]
        if mode:
            args.append(f"--mode={mode}")
        env_extra = {"LD_LIBRARY_PATH": f"{p.logicrep_lib}:{os.environ.get('LD_LIBRARY_PATH', '')}"}
        op_timeout = self.timeout.get(action)
        rc, out, err = run_python_as_user(
            script, args, self.user,
            log_file=p.log_file, timeout=op_timeout,
            env_extra=env_extra,
        )
        if rc != 0:
            raise CommandError(f"logicrep_ctl.py {action}", rc, out, err)

    def _watchdog_running(self):
        rc, out, _ = exec_popen(
            f'ps -ef | grep "{self.paths.watchdog_sh} -n logicrep -N" | grep -v grep | awk \'{{print $2}}\'',
        )
        return bool(out.strip())

    def _logicrep_process_running(self):
        rc, out, _ = exec_popen(
            'ps -ef | grep ZLogCatcherMain | grep -v grep | awk \'{print $2}\'',
        )
        return bool(out.strip())

    def _check_and_create_home(self):
        p = self.paths
        ensure_dir(p.tools_home, 0o755)
        ensure_dir(p.log_dir, 0o750)
        if not os.path.isfile(p.log_file):
            open(p.log_file, "a").close()
            os.chmod(p.log_file, 0o640)
        chown_recursive(p.log_dir, self.user_group)

    def _chown_mod_scripts(self):
        for f in os.listdir(CUR_DIR):
            fpath = os.path.join(CUR_DIR, f)
            if os.path.isfile(fpath) and f != "appctl.sh":
                exec_popen(f'chown {self.user_group} "{fpath}"')
        for f in glob.glob(os.path.join(CUR_DIR, "*.py")):
            os.chmod(f, 0o400)
        for f in glob.glob(os.path.join(CUR_DIR, "*.sh")):
            os.chmod(f, 0o400)
        zlogicrep = os.path.join(os.path.dirname(os.path.dirname(CUR_DIR)), "zlogicrep")
        if os.path.isdir(zlogicrep):
            exec_popen(f'find "{zlogicrep}" -type f -print0 | xargs -0 chmod 600')
            exec_popen(f'find "{zlogicrep}" -type f \\( -name "*.sh" -o -name "*.so" \\) -exec chmod 500 {{}} \\;')
            exec_popen(f'find "{zlogicrep}" -type d -print0 | xargs -0 chmod 700')

    def _get_newest_so(self, so_path):
        """Get newest so files from so_path."""
        so_map = self._cfg.so_names
        result = {}
        if not os.path.isdir(so_path):
            return result
        files = sorted(os.listdir(so_path), reverse=True)
        for base_name, link_name in so_map.items():
            for f in files:
                if os.path.isfile(os.path.join(so_path, f)) and f.startswith(base_name):
                    result[f] = link_name
                    break
        return result

    def _copy_bin(self, so_path):
        """Copy dependency so and jar to logicrep/lib."""
        if not so_path:
            return
        p = self.paths
        driver = self._cfg.driver_name
        driver_src = os.path.join(so_path, driver)
        if os.path.isfile(driver_src):
            shutil.copy2(driver_src, p.logicrep_lib)

        so_map = self._get_newest_so(so_path)
        for real_name, link_name in so_map.items():
            src = os.path.join(so_path, real_name)
            dst = os.path.join(p.logicrep_lib, real_name)
            link_dst = os.path.join(p.logicrep_lib, link_name)
            for old in (dst, link_dst):
                if os.path.exists(old) or os.path.islink(old):
                    os.remove(old)
            shutil.copy2(src, dst)
            os.chmod(dst, 0o500)
            os.symlink(dst, link_dst)

        chown_recursive(p.tools_root, self.user_group)

    def _copy_logicrep(self):
        """Python port of copy_logicrep."""
        p = self.paths
        ensure_dir(p.tools_root, 0o750)
        exec_popen(f'chmod 755 "{os.path.dirname(p.tools_root)}"')

        if os.path.isdir(p.logicrep_home):
            shutil.rmtree(p.logicrep_home)
        if os.path.realpath(CUR_DIR) != os.path.realpath(p.tools_scripts):
            if os.path.isdir(p.tools_scripts):
                shutil.rmtree(p.tools_scripts)
            shutil.copytree(CUR_DIR, p.tools_scripts)

        if self.node_id == "0":
            for sub in ("binlog", "logicrep_conf"):
                d = os.path.join(self.archive_path, sub)
                if os.path.isdir(d):
                    shutil.rmtree(d)
                os.makedirs(d, mode=0o770, exist_ok=True)
            conf_dir = os.path.join(self.archive_path, "logicrep_conf")
            for f in ("init.properties",):
                src = os.path.join(self.logicrep_pkg, "conf", f)
                if os.path.isfile(src):
                    shutil.copy2(src, conf_dir)
            repconf_src = os.path.join(self.logicrep_pkg, "conf", "repconf", "repconf_db.xml")
            if os.path.isfile(repconf_src):
                shutil.copy2(repconf_src, conf_dir)
            exec_popen(f'chmod 660 "{conf_dir}"/*')
            chown_recursive(self.archive_path + "/{binlog,logicrep_conf}",
                            f"{self.user}:{self.deploy_group}")

        shutil.copytree(self.logicrep_pkg, p.logicrep_home)
        sec_dir = os.path.join(p.logicrep_home, "conf", "sec")
        if os.path.isdir(sec_dir):
            shutil.rmtree(sec_dir)
        os.makedirs(sec_dir, exist_ok=True)
        for f in ("primary_keystore.ks", "standby_keystore.ks"):
            open(os.path.join(sec_dir, f), "a").close()
        exec_popen(f'chmod 600 "{sec_dir}"/*')

        kmc_src = p.kmc_shared_dir
        if os.path.isdir(kmc_src):
            exec_popen(f'cp -a "{kmc_src}"/* "{p.logicrep_lib}"')

        jars = glob.glob(os.path.join(p.logicrep_home, "com.huawei.ograc.logicrep-*.jar"))
        if jars:
            link = os.path.join(p.logicrep_home, "com.huawei.ograc.logicrep.jar")
            if os.path.islink(link):
                os.remove(link)
            os.symlink(jars[0], link)

        conf_dir_remote = os.path.join(self.archive_path, "logicrep_conf")
        for fname, target in [
            ("init.properties", os.path.join(p.logicrep_home, "conf", "init.properties")),
            ("repconf_db.xml", os.path.join(p.logicrep_home, "conf", "repconf", "repconf_db.xml")),
        ]:
            if os.path.exists(target) or os.path.islink(target):
                os.remove(target)
            src = os.path.join(conf_dir_remote, fname)
            if os.path.isfile(src):
                os.symlink(src, target)

        exec_popen(f'chmod 750 "{p.logicrep_home}" "{p.tools_root}"')

        if self.node_id == "0":
            user_file = p.user_file
            open(user_file, "a").close()
            os.chmod(user_file, 0o400)

        chown_recursive(p.tools_root, self.user_group)

    def _safe_update(self, so_path=""):
        """Python port of safe_update."""
        p = self.paths
        version_first = "0"
        if os.path.isfile(p.versions_yml):
            with open(p.versions_yml, encoding="utf-8") as f:
                for line in f:
                    if "Version:" in line:
                        ver = line.split(":")[1].strip().split(".")[0]
                        version_first = ver
                        break

        if version_first != "2":
            if os.path.realpath(CUR_DIR) != os.path.realpath(p.tools_scripts):
                if os.path.isdir(p.tools_scripts):
                    shutil.rmtree(p.tools_scripts)
                shutil.copytree(CUR_DIR, p.tools_scripts)

            jar_link = os.path.join(p.logicrep_home, "com.huawei.ograc.logicrep.jar")
            if os.path.islink(jar_link):
                os.remove(jar_link)

            keep = {"libssl.", "libcrypto.", "libstdc++.", "libsql2bl."}
            lib_dir = p.logicrep_lib
            if os.path.isdir(lib_dir):
                for f in os.listdir(lib_dir):
                    fp = os.path.join(lib_dir, f)
                    if os.path.isfile(fp) and not any(f.startswith(k) for k in keep):
                        os.remove(fp)

            for item in ("com.huawei.ograc.logicrep-*.jar",):
                for src in glob.glob(os.path.join(self.logicrep_pkg, item)):
                    shutil.copy2(src, p.logicrep_home)
            for d in ("lib",):
                src_d = os.path.join(self.logicrep_pkg, d)
                if os.path.isdir(src_d):
                    exec_popen(f'cp -arf "{src_d}"/* "{os.path.join(p.logicrep_home, d)}"')
            for f in ("repconf_db_confige.py", "shutdown_all_logicrep.sh",
                       "shutdown.sh", "startup.sh", "watchdog_logicrep.sh", "watchdog_shutdown.sh"):
                src = os.path.join(self.logicrep_pkg, f)
                if os.path.isfile(src):
                    shutil.copy2(src, p.logicrep_home)

            self._copy_bin(so_path)

            kmc_src = p.kmc_shared_dir
            if os.path.isdir(kmc_src):
                exec_popen(f'cp -a "{kmc_src}"/* "{p.logicrep_lib}"')

            jars = glob.glob(os.path.join(p.logicrep_home, "com.huawei.ograc.logicrep-*.jar"))
            if jars:
                link = os.path.join(p.logicrep_home, "com.huawei.ograc.logicrep.jar")
                if os.path.islink(link):
                    os.remove(link)
                os.symlink(jars[0], link)

            exec_popen(f'chmod 600 "{self.startup_lock}" 2>/dev/null')
            chown_recursive(p.tools_root, self.user_group)
        else:
            self.action_install()

    def _check_startup_status(self):
        """Wait for logicrep startup to complete."""
        timeout = 900
        while timeout > 0:
            time.sleep(1)
            timeout -= 1
            if not os.path.isfile(self.startup_status_file):
                continue
            with open(self.startup_status_file, "r") as f:
                status = f.read().strip()
            if status == "started":
                LOG.info("--------logicrep startup success--------")
                return True
            if timeout % 10 == 0:
                LOG.info(f"Current status: {status}, Remaining timeout: {timeout}s")
        return False

    def _check_status(self):
        """Check status (Python port)."""
        p = self.paths
        if os.path.isfile(p.flag_file) and not self._watchdog_running():
            raise RuntimeError("Logicrep watchdog process is offline.")
        if os.path.isfile(p.enable_file) and not self._logicrep_process_running():
            raise RuntimeError("Logicrep process is offline.")

    def action_start(self, start_mode="active"):
        p = self.paths
        if os.path.isfile(p.user_file) and self.install_type == "override":
            self._run_ctl("start", mode=start_mode)
            os.remove(p.user_file)
        self._run_ctl("set_resource_limit", mode=start_mode)

    def action_startup(self, bin_path=""):
        p = self.paths
        exec_popen("sysctl -w kernel.sched_rt_runtime_us=-1")
        self._copy_bin(bin_path)
        self._run_ctl("startup")
        open(p.flag_file, "a").close()
        os.chmod(p.flag_file, 0o400)
        exec_popen(f'chown -h {self.user_group} "{p.flag_file}"')

        if not self._watchdog_running():
            run_shell_as_user(
                f'nohup sh {p.watchdog_sh} -n logicrep -N {self.node_count} &',
                self.user, timeout=10,
            )
            if not self._check_startup_status():
                raise RuntimeError("logicrep startup timeout")

    def action_shutdown(self):
        p = self.paths
        if os.path.isfile(p.flag_file):
            os.remove(p.flag_file)
        run_shell_as_user(f'sh {p.watchdog_shutdown_sh} -n logicrep -f', self.user)
        self._run_ctl("shutdown")
        if os.path.isfile(p.enable_file):
            os.remove(p.enable_file)

    def action_stop(self):
        p = self.paths
        run_shell_as_user(f'sh {p.watchdog_shutdown_sh} -n logicrep -f', self.user)
        self._run_ctl("stop")
        if os.path.isfile(p.enable_file):
            os.remove(p.enable_file)

    def action_install(self):
        self._chown_mod_scripts()
        if self.in_container == "0":
            self._copy_logicrep()
        self._run_ctl("install")

    def action_init_container(self):
        self._copy_logicrep()
        self._run_ctl("init_container")

    def action_uninstall(self):
        p = self.paths
        if os.path.isdir(p.logicrep_home):
            shutil.rmtree(p.logicrep_home)
        for f in (self.startup_lock, self.startup_status_file):
            if os.path.isfile(f):
                os.remove(f)

    def action_pre_upgrade(self):
        inspection_dir = os.path.join(os.path.dirname(CUR_DIR), "inspection")
        if os.path.isdir(inspection_dir):
            chown_recursive(inspection_dir, self.user_group)
        exec_popen(f'chmod 600 "{self.startup_lock}" 2>/dev/null')
        chown_recursive(f'"{self.startup_lock}"', self.user_group)
        self._chown_mod_scripts()
        self._run_ctl("pre_upgrade")

    def action_upgrade_backup(self, backup_path=""):
        p = self.paths
        if os.path.isdir(p.logicrep_home) and backup_path:
            dst = os.path.join(backup_path, "logicrep")
            os.makedirs(dst, mode=0o750, exist_ok=True)
            shutil.copytree(p.logicrep_home, os.path.join(dst, "logicrep"))

    def action_upgrade(self, so_path=""):
        self._safe_update(so_path)

    def action_rollback(self, backup_path=""):
        p = self.paths
        src = os.path.join(backup_path, "logicrep", "logicrep")
        if not os.path.isdir(src):
            LOG.info("No logicrep backup found, skip rollback")
            return
        if os.path.isdir(p.logicrep_home):
            shutil.rmtree(p.logicrep_home)
        shutil.copytree(src, p.logicrep_home)

    def action_check_status(self):
        self._check_status()
        inspection_dir = os.path.join(os.path.dirname(CUR_DIR), "inspection")
        if os.path.isdir(inspection_dir):
            chown_recursive(inspection_dir, self.user_group)
        self._run_ctl("pre_upgrade")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 logicrep_deploy.py <action> [args...]", file=sys.stderr)
        sys.exit(1)

    deployer = LogicrepDeploy()
    deployer._check_and_create_home()

    action = sys.argv[1]
    backup_path = sys.argv[2] if len(sys.argv) > 2 else ""
    start_mode = sys.argv[2] if len(sys.argv) > 2 else "active"
    so_path = sys.argv[4] if len(sys.argv) > 4 else ""

    action_map = {
        "start": lambda: deployer.action_start(start_mode),
        "startup": lambda: deployer.action_startup(sys.argv[2] if len(sys.argv) > 2 else ""),
        "shutdown": deployer.action_shutdown,
        "stop": deployer.action_stop,
        "install": deployer.action_install,
        "init_container": deployer.action_init_container,
        "uninstall": deployer.action_uninstall,
        "pre_upgrade": deployer.action_pre_upgrade,
        "upgrade_backup": lambda: deployer.action_upgrade_backup(backup_path),
        "upgrade": lambda: deployer.action_upgrade(so_path),
        "rollback": lambda: deployer.action_rollback(backup_path),
        "check_status": deployer.action_check_status,
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
