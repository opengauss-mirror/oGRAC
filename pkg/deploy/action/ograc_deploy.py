"""
oGRAC 部署编排器（重构版）

以 root 身份运行，负责：
  - 调度各子操作（pre_install, install, start, stop, uninstall, ...）
  - 调用各组件模块的 appctl.sh
  - 权限管理、用户创建
  - 通过 run_python_as_user 切换用户执行业务逻辑

已剔除 dbstor 逻辑，保证容器流程正常。
"""

import os
import shlex
import shutil
import sys
import subprocess

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, CUR_DIR)

from config import get_config, cfg
from log_config import get_logger
from utils import (
    exec_popen, run_cmd, run_as_user, run_python_as_user,
    ensure_dir, safe_remove, copy_tree, chown_recursive,
    read_version, CommandError,
)

LOG = get_logger("deploy")

PRE_INSTALL_ORDER = ["ograc", "cms", "dss"]
INSTALL_ORDER = ["cms", "dss", "ograc"]
START_ORDER = ["cms", "dss", "ograc"]
STOP_ORDER = ["cms", "dss", "ograc"]
UNINSTALL_ORDER = ["ograc", "dss", "cms"]
BACKUP_ORDER = ["ograc", "dss", "cms", "og_om"]
CHECK_STATUS_ORDER = ["ograc", "cms", "dss", "og_om", "ograc_exporter"]
PRE_UPGRADE_ORDER = ["og_om", "ograc_exporter", "cms", "ograc"]
UPGRADE_ORDER = ["og_om", "ograc_exporter", "cms", "ograc"]
POST_UPGRADE_ORDER = ["og_om", "ograc_exporter", "cms", "ograc"]
ROLLBACK_ORDER = ["cms", "ograc", "og_om", "ograc_exporter"]
INIT_CONTAINER_ORDER = ["cms", "ograc"]


class OgracDeploy:
    """oGRAC 部署编排器。"""

    def __init__(self):
        self.cfg = get_config()
        self.paths = self.cfg.paths
        self.deploy = self.cfg.deploy
        self._sync_deploy_attrs()

        os.environ["DEPLOY_PKG_DIR"] = os.path.dirname(CUR_DIR)

    def _sync_deploy_attrs(self):
        self.ograc_user = self.deploy.ograc_user
        self.ograc_group = self.deploy.ograc_group
        self.ograc_common_group = self.deploy.ograc_common_group
        self.ogmgr_user = self.deploy.ogmgr_user
        self.deploy_mode = self.deploy.deploy_mode
        self.ograc_in_container = self.deploy.ograc_in_container
        self.node_id = self.deploy.node_id

    def _call_module(self, module, action, *extra_args):
        """调用子模块的 appctl.sh。"""
        appctl = os.path.join(self.paths.action_dir, module, "appctl.sh")
        if not os.path.exists(appctl):
            appctl = os.path.join(CUR_DIR, module, "appctl.sh")
        if not os.path.exists(appctl):
            LOG.warning("Module %s appctl.sh not found, skipping", module)
            return 0

        cmd = f"sh {appctl} {action}"
        if extra_args:
            cmd += " " + " ".join(str(a) for a in extra_args)

        LOG.info("Calling %s %s", module, action)
        ret, stdout, stderr = exec_popen(
            cmd, timeout=self.cfg.timeout(action) or 1800)
        if ret != 0:
            details = "\n".join(part for part in (stdout.strip(), stderr.strip()) if part)
            LOG.error("%s %s failed: %s", module, action, details)
        else:
            LOG.info("%s %s success", module, action)
        return ret

    def pre_install(self, install_type="override", config_file=""):
        LOG.info("Begin pre_install, install_type=%s", install_type)

        if self.ograc_in_container not in ("1", "2"):
            pre_install_py = os.path.join(CUR_DIR, "pre_install.py")
            ret, stdout, stderr = exec_popen(
                f"python3 {pre_install_py} {install_type} {config_file}",
                timeout=self.cfg.timeout("pre_install"))
            if ret != 0:
                LOG.error("pre_install.py failed: %s", stderr)
                return 1
        else:
            config_path = os.path.join(CUR_DIR, config_file) if config_file else ""
            if config_path and os.path.exists(config_path):
                deploy_param = os.path.join(CUR_DIR, "deploy_param.json")
                copy_tree(config_path, deploy_param)

        config_dir = os.path.join(os.path.dirname(CUR_DIR), "config")
        deploy_param_src = os.path.join(CUR_DIR, "deploy_param.json")
        if os.path.exists(deploy_param_src):
            os.rename(deploy_param_src, os.path.join(config_dir, "deploy_param.json"))

        self.deploy.write_param("install_type", install_type)
        self._reload_config()

        self._init_user_and_group()
        self._correct_files_mod()

        for module in PRE_INSTALL_ORDER:
            ret = self._call_module(module, "pre_install", install_type)
            if ret != 0:
                LOG.error("pre_install %s failed", module)
                return 1
            LOG.info("pre_install %s success", module)

        LOG.info("pre_install completed successfully")
        return 0

    def install(self, install_type="override", config_file=""):
        LOG.info("Begin install, install_type=%s", install_type)

        self._reload_config()
        config_install_type = self.deploy.get("install_type", "override")
        mes_ssl_switch = self.deploy.mes_ssl_switch

        if config_install_type == "override":
            self._create_common_dirs()
            self._mount_fs()
            if mes_ssl_switch:
                self._copy_certificate()

        self._install_ograc_package()
        self._copy_resources()

        for module in INSTALL_ORDER:
            LOG.info("Installing %s", module)
            if module == "ograc":
                ret = self._call_module(module, "install")
            else:
                ret = self._call_module(module, "install")
            if ret != 0:
                LOG.error("Install %s failed", module)
                return 1
            LOG.info("Install %s success", module)

        self._config_security_limits()
        self._show_version()

        LOG.info("install completed successfully")
        return 0

    def start(self, start_mode=""):
        LOG.info("Begin start")
        self._init_limits_config()

        for module in START_ORDER:
            LOG.info("Starting %s", module)
            ret = self._call_module(module, "start", start_mode)
            if ret != 0:
                LOG.error("Start %s failed", module)
                return 1
            LOG.info("Start %s success", module)

        self._start_daemon()
        self._start_systemd_timers()

        LOG.info("start completed successfully")
        return 0

    def stop(self):
        LOG.info("Begin stop")
        ensure_dir(os.path.dirname(self.paths.stop_enable))
        open(self.paths.stop_enable, 'a').close()

        if self.ograc_in_container == "0":
            self._stop_systemd_timers()

        self._stop_daemon()
        self._kill_user_processes("cms_start2.sh -start")

        for module in STOP_ORDER:
            LOG.info("Stopping %s", module)
            ret = self._call_module(module, "stop")
            if ret != 0:
                LOG.error("Stop %s failed", module)
                return 1
            LOG.info("Stop %s success", module)

        LOG.info("stop completed successfully")
        return 0

    def uninstall(self, uninstall_type="override", force_type=""):
        LOG.info("Begin uninstall, type=%s", uninstall_type)
        self._reload_config()
        self.deploy.write_param("uninstall_type", uninstall_type)

        self._clear_security_limits()
        self._clear_residual_files()

        for module in UNINSTALL_ORDER:
            LOG.info("Uninstalling %s", module)
            args = [uninstall_type]
            if force_type:
                args.append(force_type)
            ret = self._call_module(module, "uninstall", *args)
            if ret != 0:
                LOG.error("Uninstall %s failed", module)
                return 1
            LOG.info("Uninstall %s success", module)

        if uninstall_type == "override":
            self._umount_fs()
            self._cleanup_override()

        LOG.info("uninstall completed successfully")
        return 0

    def check_status(self):
        LOG.info("Begin check_status")
        all_online = True
        all_offline = True

        for module in CHECK_STATUS_ORDER:
            ret = self._call_module(module, "check_status")
            if ret == 0:
                LOG.info("%s is online", module)
                all_offline = False
            else:
                LOG.error("%s is offline", module)
                all_online = False

        daemon_running = self._is_daemon_running()
        if daemon_running:
            all_offline = False
        else:
            all_online = False

        if all_online:
            LOG.info("All processes are online")
            return 0
        if all_offline:
            LOG.error("All processes are offline")
            return 1
        LOG.info("Partial online")
        return 2

    def backup(self):
        LOG.info("Begin backup")
        for module in BACKUP_ORDER:
            ret = self._call_module(module, "backup")
            if ret != 0:
                LOG.error("Backup %s failed", module)
                return 1
        LOG.info("backup completed successfully")
        return 0

    def init_container(self):
        LOG.info("Begin init_container")
        for module in INIT_CONTAINER_ORDER:
            LOG.info("Init %s", module)
            ret = self._call_module(module, "init_container")
            if ret != 0:
                LOG.error("Init %s failed", module)
                return 1
            LOG.info("Init %s success", module)
        LOG.info("init_container completed successfully")
        return 0

    def certificate(self, *args):
        LOG.info("Begin certificate operations")
        cert_script = os.path.join(
            CUR_DIR, "implement", "certificate_update_and_revocation.py")
        cmd = f"python3 -B {cert_script} " + " ".join(args)
        ret, _, stderr = exec_popen(cmd)
        if ret != 0:
            LOG.error("Certificate operation failed: %s", stderr)
        return ret

    def config_opt(self, *args):
        LOG.info("Begin config_opt")
        script = os.path.join(CUR_DIR, "implement", "config_opt.py")
        cmd = f"python3 -B {script} " + " ".join(args)
        ret, _, stderr = exec_popen(cmd)
        if ret != 0:
            LOG.error("config_opt failed: %s", stderr)
        return ret

    def clear_upgrade_backup(self):
        LOG.info("Begin clear_upgrade_backup")
        script = os.path.join(CUR_DIR, "upgrade", "clear_upgrade_backup.py")
        ret, _, stderr = exec_popen(f"python3 {script}")
        if ret != 0:
            LOG.error("clear_upgrade_backup failed: %s", stderr)
            return 1
        LOG.info("clear_upgrade_backup success")
        return 0


    def _reload_config(self):
        from config import reset_config, get_config
        reset_config()
        self.cfg = get_config()
        self.deploy = self.cfg.deploy
        self.paths = self.cfg.paths
        self._sync_deploy_attrs()

    def _init_user_and_group(self):
        LOG.info("Initializing users and groups")
        deploy_user = self.deploy.get("deploy_user")
        deploy_group = self.deploy.get("deploy_group")
        svc_user = self.ograc_user
        svc_group = self.ograc_group
        common_group = self.ograc_common_group
        ogmgr = self.ogmgr_user

        self._ensure_group(svc_group)
        self._ensure_group(common_group)
        self._ensure_user(svc_user, svc_group, f"/home/{svc_user}")
        self._ensure_user(ogmgr, svc_group, f"/home/{ogmgr}")

        exec_popen(f"usermod -a -G {common_group} {deploy_user}")
        exec_popen(f"usermod -a -G {common_group} {svc_user}")
        exec_popen(f"usermod -a -G {common_group} {ogmgr}")
        exec_popen(f"usermod -a -G {deploy_group} {svc_user}")
        self._append_user_to_existing_group(svc_user, "ubsmd")

        import pwd
        for u in (svc_user, ogmgr):
            try:
                home = pwd.getpwnam(u).pw_dir
            except KeyError:
                continue
            if os.path.isdir(home):
                exec_popen(f"chown {u}:{svc_group} {home}")
                os.chmod(home, 0o700)

    @staticmethod
    def _ensure_group(name):
        ret, _, _ = exec_popen(f"getent group {name}")
        if ret == 0:
            return
        ret, stdout, stderr = exec_popen(f"groupadd {name}")
        if ret != 0:
            LOG.error("groupadd %s failed: %s %s", name, stdout, stderr)
            raise RuntimeError(f"groupadd {name} failed: {stderr}")

    @staticmethod
    def _ensure_user(name, group, home):
        ret, _, _ = exec_popen(f"id {name}")
        if ret == 0:
            return
        ret, stdout, stderr = exec_popen(
            f"useradd {name} -g {group} -m -d {home} -s /sbin/nologin")
        if ret != 0:
            LOG.error("useradd %s failed: %s %s", name, stdout, stderr)
            raise RuntimeError(f"useradd {name} failed: {stderr}")

    @staticmethod
    def _append_user_to_existing_group(user, group):
        ret, _, _ = exec_popen(f"getent group {group}")
        if ret != 0:
            LOG.info("Skip adding %s to optional group %s: group not found", user, group)
            return
        ret, stdout, stderr = exec_popen(f"usermod -a -G {group} {user}")
        if ret != 0:
            LOG.warning("Failed to add %s to group %s: %s %s", user, group, stdout, stderr)

    def _correct_files_mod(self):
        LOG.info("Correcting file permissions")
        pkg_dir = os.path.dirname(CUR_DIR)
        batch_400 = [
            (CUR_DIR, 1), (os.path.join(pkg_dir, "config"), 1),
            (os.path.join(pkg_dir, "common"), None),
            (os.path.join(CUR_DIR, "implement"), None),
            (os.path.join(CUR_DIR, "utils"), None),
            (os.path.join(CUR_DIR, "logic"), None),
            (os.path.join(CUR_DIR, "storage_operate"), None),
            (os.path.join(CUR_DIR, "inspection"), None),
            (os.path.join(CUR_DIR, "wsr"), None),
            (os.path.join(CUR_DIR, "wsr_report"), None),
        ]
        for d, depth in batch_400:
            if not os.path.isdir(d):
                continue
            cmd = f'find "{d}"/'
            if depth:
                cmd += f' -maxdepth {depth}'
            cmd += ' -type f -print0 | xargs -0 chmod 400'
            exec_popen(cmd)

        for d in (CUR_DIR, os.path.join(CUR_DIR, "logic")):
            if os.path.isdir(d):
                exec_popen(f'find "{d}"/ -maxdepth 1 -type d -print0 | xargs -0 chmod 755')

        special = {
            os.path.join(pkg_dir, "common"): 0o755,
            CUR_DIR: 0o755,
            os.path.join(pkg_dir, "config"): 0o755,
            os.path.join(CUR_DIR, "config_params_lun.json"): 0o755,
            os.path.join(pkg_dir, "config", "deploy_param.json"): 0o644,
            os.path.join(pkg_dir, "config", "dr_deploy_param.json"): 0o644,
            os.path.join(pkg_dir, "versions.yml"): 0o644,
            os.path.join(CUR_DIR, "inspection"): 0o750,
        }
        for path, mode in special.items():
            if os.path.exists(path):
                try:
                    os.chmod(path, mode)
                except OSError:
                    pass

    def _create_common_dirs(self):
        LOG.info("Creating common directories")
        user_group = f"{self.ograc_user}:{self.ograc_group}"

        ensure_dir(os.path.join(self.paths.ograc_home, "image"), mode=0o755)
        ensure_dir(os.path.join(self.paths.common_dir, "data"), mode=0o750)
        ensure_dir(os.path.join(self.paths.common_dir, "socket"), mode=0o755)
        ensure_dir(self.paths.common_config_dir, mode=0o755)

        data_root = self.paths.data_root
        data_local = self.paths.data_local
        ensure_dir(data_root, mode=0o755)
        ensure_dir(data_local, mode=0o755)

        ograc_data_base = os.path.join(data_local, "ograc")
        for sub in ("", "tmp", os.path.join("tmp", "data")):
            d = os.path.join(ograc_data_base, sub) if sub else ograc_data_base
            ensure_dir(d, mode=0o750)

        exec_popen(f"chown -R {user_group} {ograc_data_base}")
        exec_popen(f"chown {user_group} {self.paths.ograc_home}")
        exec_popen(f"chown {user_group} {data_local}")

    def _install_ograc_package(self):
        """安装 oGRAC 软件包 —— 已剔除 dbstor 安装逻辑。"""
        LOG.info("Installing oGRAC package")
        tar_pattern = os.path.join(os.path.dirname(CUR_DIR), "repo", "ograc-*.tar.gz")
        import glob
        tar_files = glob.glob(tar_pattern)
        if not tar_files:
            LOG.error("oGRAC tar.gz not found")
            return 1

        install_base = os.path.join(self.paths.ograc_home, "image")
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

        return 0

    def _copy_resources(self):
        """将部署包 action/ 整体拷贝到安装目录 /opt/ograc/action/。

        包含：
          - 顶层共享模块（config.py, utils.py, log_config.py …）
          - 所有组件子目录（cms/, dss/, ograc/, og_om/, …）
          - config/ 与 common/ 辅助目录
        """
        LOG.info("Copying resources to install path")
        if os.path.isfile(self.paths.rpm_flag):
            return

        action_dst = self.paths.action_dir
        ensure_dir(action_dst, mode=0o755)

        _SKIP = {"__pycache__"}

        for item in os.listdir(CUR_DIR):
            if item in _SKIP:
                continue
            src = os.path.join(CUR_DIR, item)
            dst = os.path.join(action_dst, item)
            if os.path.isdir(src):
                copy_tree(src, dst)
            else:
                shutil.copy2(src, dst)

        pkg_dir = os.path.dirname(CUR_DIR)
        for extra in ("config", "common"):
            src = os.path.join(pkg_dir, extra)
            dst = os.path.join(self.paths.ograc_home, extra)
            if os.path.isdir(src):
                copy_tree(src, dst)

        versions_src = os.path.join(pkg_dir, "versions.yml")
        if os.path.isfile(versions_src):
            shutil.copy2(versions_src, os.path.join(self.paths.ograc_home, "versions.yml"))

        repo_src = os.path.join(pkg_dir, "repo")
        if os.path.isdir(repo_src):
            copy_tree(repo_src, os.path.join(self.paths.ograc_home, "repo"))

        pkg_marker = os.path.join(action_dst, ".deploy_pkg_dir")
        with open(pkg_marker, "w") as f:
            f.write(os.path.dirname(CUR_DIR))

        self._fix_action_permissions(action_dst)

    def _fix_action_permissions(self, action_dst):
        """设置安装目录下脚本的属主和权限。

        root 调用 appctl.sh → xxx_deploy.py（root 身份）
        xxx_deploy.py 通过 run_python_as_user 切换到 ograc_user 运行 xxx_ctl.py
        因此：
          - 目录和 .py 文件属主 = ograc_user，权限 owner 读 + group 读（root 也能读）
          - appctl.sh 属主 = root
        """
        user_group = f"{self.ograc_user}:{self.ograc_group}"

        exec_popen(f'find "{action_dst}" -type d -exec chmod 755 {{}} +')
        exec_popen(f'find "{action_dst}" -type f -name "*.py" -exec chmod 644 {{}} +')
        exec_popen(f'find "{action_dst}" -type f -name "*.sh" -exec chmod 755 {{}} +')
        exec_popen(f'find "{action_dst}" -type f -name "*.json" -exec chmod 644 {{}} +')

        exec_popen(f'chown -R {user_group} "{action_dst}"')

        for module in ("cms", "dss", "ograc", "og_om", "ograc_exporter",
                        "logicrep", "dbstor", "docker"):
            appctl = os.path.join(action_dst, module, "appctl.sh")
            if os.path.isfile(appctl):
                exec_popen(f"chown root:root {appctl}")

    def _mount_fs(self):
        """挂载文件系统 —— 已剔除 dbstor 特有的挂载逻辑。"""
        if self.ograc_in_container != "0":
            return
        if self.deploy_mode in ("dbstor", "dss"):
            return

        LOG.info("Mounting file systems")
        storage_share_fs = self.deploy.storage_share_fs
        storage_archive_fs = self.deploy.storage_archive_fs
        storage_metadata_fs = self.deploy.storage_metadata_fs

        if storage_metadata_fs:
            metadata_dir = self.paths.metadata_path(storage_metadata_fs)
            ensure_dir(metadata_dir, mode=0o755)
            metadata_ip = self.deploy.get("metadata_logic_ip")
            if metadata_ip:
                exec_popen(
                    f"mount -t nfs -o timeo=50,nosuid,nodev "
                    f"{metadata_ip}:/{storage_metadata_fs} {metadata_dir}")

        if storage_archive_fs:
            archive_dir = self.paths.archive_path(storage_archive_fs)
            ensure_dir(archive_dir, mode=0o750)
            archive_ip = self.deploy.get("archive_logic_ip")
            if archive_ip:
                exec_popen(
                    f"mount -t nfs -o timeo=50,nosuid,nodev "
                    f"{archive_ip}:/{storage_archive_fs} {archive_dir}")

        if self.deploy_mode == "file" and storage_share_fs:
            share_dir = self.paths.share_path(storage_share_fs)
            ensure_dir(share_dir, mode=0o750)
            share_ip = self.deploy.get("share_logic_ip")
            if share_ip:
                exec_popen(
                    f"mount -t nfs -o vers=4.0,timeo=50,nosuid,nodev "
                    f"{share_ip}:/{storage_share_fs} {share_dir}")

    def _umount_fs(self):
        """卸载文件系统。"""
        if self.ograc_in_container != "0":
            return
        LOG.info("Unmounting file systems")
        for fs_type in ("share", "archive", "metadata", "storage"):
            fs_name = self.deploy.get(f"storage_{fs_type}_fs", "")
            if fs_name:
                mount_point = os.path.join(
                    self.paths.data_remote, f"{fs_type}_{fs_name}")
                exec_popen(f"umount -f -l {mount_point} > /dev/null 2>&1")
                safe_remove(mount_point)

    def _copy_certificate(self):
        """复制证书文件。"""
        if self.ograc_in_container != "0":
            return
        LOG.info("Copying certificates")
        cert_dir = self.paths.certificates_dir
        safe_remove(cert_dir)
        ensure_dir(cert_dir, mode=0o700)

        for key, name in [("ca_path", "ca.crt"), ("crt_path", "mes.crt"),
                          ("key_path", "mes.key")]:
            src = self.deploy.get(key)
            if src and os.path.exists(src):
                copy_tree(src, os.path.join(cert_dir, name))

        chown_recursive(cert_dir, self.ograc_user, self.ograc_group)

    def _config_security_limits(self):
        """配置 /etc/security/limits.conf。"""
        LOG.info("Configuring security limits")
        limits_file = "/etc/security/limits.conf"
        if not os.path.exists(limits_file):
            return
        entries = [
            f"{self.ograc_user} hard nice -20",
            f"{self.ograc_user} soft nice -20",
            "* soft memlock unlimited",
            "* hard memlock unlimited",
        ]
        try:
            with open(limits_file, "r") as f:
                content = f.read()
            for entry in entries:
                if entry not in content:
                    with open(limits_file, "a") as f:
                        f.write(f"\n{entry}")
        except OSError as e:
            LOG.warning("Failed to configure limits: %s", e)

    def _clear_security_limits(self):
        """清理当前实例写入的 limits 条目。"""
        LOG.info("Clearing security limits")
        limits_file = "/etc/security/limits.conf"
        if not os.path.exists(limits_file):
            return
        patterns = [
            f"/^{self.ograc_user} hard nice -20$/d",
            f"/^{self.ograc_user} soft nice -20$/d",
            f"/^{self.ograc_user} hard nofile /d",
            f"/^{self.ograc_user} soft nofile /d",
        ]
        for pattern in patterns:
            exec_popen(f"sed -i '{pattern}' {limits_file}")

    def _show_version(self):
        """写入版本信息到 /usr/local/bin/show。"""
        LOG.info("Writing version info")
        versions_file = self.paths.versions_yml
        version = read_version(versions_file)
        show_script = "/usr/local/bin/show"
        try:
            with open(show_script, "w") as f:
                f.write(f"""#!/bin/bash
sn=$(dmidecode -s system-uuid)
name=$(cat /etc/hostname)
echo "SN : ${{sn}}"
echo "System Name : ${{name}}"
echo "Product Model : ograc"
echo "Product Version : {version}"
""")
            os.chmod(show_script, 0o550)
        except OSError:
            pass

    def _start_daemon(self):
        """启动守护进程。"""
        LOG.info("Starting daemon")
        cms_reg = os.path.join(self.paths.action_dir, "cms", "cms_reg.sh")
        run_as_user(f"sh {cms_reg} enable", self.ograc_user)
        daemon_script = self.paths.ograc_service_script
        if os.path.exists(daemon_script):
            exec_popen(f"sh {daemon_script} start")

    def _stop_daemon(self):
        """停止守护进程。"""
        LOG.info("Stopping daemon")
        daemon_script = self.paths.ograc_service_script
        self._kill_user_processes(f"sh {daemon_script} start")
        if os.path.exists(daemon_script):
            exec_popen(f"sh {daemon_script} stop")

    def _kill_user_processes(self, pattern, user=None):
        target_user = user or self.ograc_user
        cmd = (
            f"ps -u {target_user} -o pid=,args= | grep '{pattern}' | "
            "grep -v grep | awk '{print $1}'"
        )
        ret, stdout, _ = exec_popen(cmd)
        if ret != 0 or not stdout.strip():
            return
        for pid in stdout.strip().splitlines():
            exec_popen(f"kill -9 {pid}")

    def _is_daemon_running(self):
        cmd = (
            f"ps -u {self.ograc_user} -o pid=,args= | "
            f"grep '{self.paths.ograc_daemon_script}' | grep -v grep"
        )
        ret, stdout, _ = exec_popen(cmd)
        return ret == 0 and bool(stdout.strip())

    def _install_systemd_units(self):
        """根据 cfg.paths 动态生成 systemd unit 文件，消除硬编码路径。"""
        service_script = self.paths.ograc_service_script
        logs_script = os.path.join(self.paths.common_script_dir, "logs_handler", "execute.py")
        units = {
            self.paths.daemon_service_unit: (
                "[Unit]\n"
                "Description=ograc daemon service\n\n"
                "[Service]\n"
                "Type=simple\n"
                "KillMode=process\n"
                f"ExecStart=/bin/bash {service_script} start\n"
            ),
            self.paths.daemon_timer_unit: (
                "[Unit]\n"
                "Description=Run every 60s and on boot\n\n"
                "[Timer]\n"
                f"Unit={self.paths.daemon_service_unit}\n"
                "OnBootSec=2min\n"
                "OnUnitActiveSec=60s\n\n"
                "[Install]\n"
                "WantedBy=multi-user.target\n"
            ),
            self.paths.logs_service_unit: (
                "[Unit]\n"
                "Description=regularly clean up the logs of each module of ograc\n\n"
                "[Service]\n"
                "Type=simple\n"
                "KillMode=process\n"
                f"ExecStart=/bin/python3 {logs_script}\n"
            ),
            self.paths.logs_timer_unit: (
                "[Unit]\n"
                "Description=Run every 60min and on boot\n\n"
                "[Timer]\n"
                f"Unit={self.paths.logs_service_unit}\n"
                "OnBootSec=2min\n"
                "OnUnitActiveSec=60min\n\n"
                "[Install]\n"
                "WantedBy=multi-user.target\n"
            ),
        }
        for name, content in units.items():
            path = os.path.join("/etc/systemd/system", name)
            try:
                with open(path, "w") as f:
                    f.write(content)
                os.chmod(path, 0o644)
            except OSError as e:
                LOG.warning("Failed to write %s: %s", path, e)

    def _cleanup_legacy_systemd_units(self):
        legacy_pairs = (
            ("ograc.service", "ograc.timer"),
            ("ograc_logs_handler.service", "ograc_logs_handler.timer"),
        )
        for service_name, timer_name in legacy_pairs:
            service_path = os.path.join("/etc/systemd/system", service_name)
            if not os.path.isfile(service_path):
                continue
            try:
                with open(service_path, encoding="utf-8") as f:
                    content = f.read()
            except OSError:
                continue
            if self.paths.ograc_home not in content:
                continue
            exec_popen(f"systemctl stop {timer_name}")
            exec_popen(f"systemctl disable {timer_name}")
            safe_remove(os.path.join("/etc/systemd/system", timer_name))
            safe_remove(service_path)

    def _start_systemd_timers(self):
        if self.ograc_in_container != "0":
            return
        LOG.info("Installing and starting systemd timers")
        self._cleanup_legacy_systemd_units()
        self._install_systemd_units()
        exec_popen("systemctl daemon-reload")
        for timer in (self.paths.daemon_timer_unit, self.paths.logs_timer_unit):
            exec_popen(f"systemctl start {timer}")
            exec_popen(f"systemctl enable {timer}")

    def _stop_systemd_timers(self):
        LOG.info("Stopping systemd timers")
        exec_popen("systemctl daemon-reload")
        for timer in (self.paths.daemon_timer_unit, self.paths.logs_timer_unit):
            exec_popen(f"systemctl stop {timer}")
            exec_popen(f"systemctl disable {timer}")

    def _init_limits_config(self):
        """配置 openfile 限制。"""
        limits_file = "/etc/security/limits.conf"
        open_file_num = 102400
        if not os.path.exists(limits_file):
            open(limits_file, 'a').close()
        exec_popen(f"sed -i '/hard nofile/d' {limits_file}")
        exec_popen(f"sed -i '/soft nofile/d' {limits_file}")
        with open(limits_file, "a") as f:
            f.write(f"\n{self.ograc_user} hard nofile {open_file_num}")
            f.write(f"\n{self.ograc_user} soft nofile {open_file_num}")

    def _clear_residual_files(self):
        """清理残留文件。"""
        LOG.info("Clearing residual files")
        storage_metadata_fs = self.deploy.storage_metadata_fs
        if storage_metadata_fs:
            metadata_dir = self.paths.metadata_path(storage_metadata_fs)
            safe_remove(os.path.join(metadata_dir, "upgrade"))
            safe_remove(os.path.join(metadata_dir, "upgrade.lock"))
            if str(self.node_id) == "0":
                safe_remove(os.path.join(metadata_dir, "deploy_param.json"))
                safe_remove(os.path.join(metadata_dir, "dr_deploy_param.json"))
                safe_remove(os.path.join(metadata_dir, "versions.yml"))
        safe_remove("/opt/backup_note")

    @staticmethod
    def _cleanup_sysv_shm_for_user(user):
        ret, stdout, stderr = exec_popen("ipcs -m")
        if ret != 0:
            LOG.warning("Failed to list shared memory: %s%s", stdout, stderr)
            return
        for line in stdout.splitlines():
            parts = line.split()
            if len(parts) < 6 or parts[0] == "key" or parts[0].startswith("------"):
                continue
            owner = parts[2]
            shm_id = parts[1]
            nattch = parts[5]
            if owner != user:
                continue
            if nattch != "0":
                LOG.info("Skip attached shm segment %s owned by %s", shm_id, user)
                continue
            ret, _, err = exec_popen(f"ipcrm -m {shm_id}")
            if ret != 0:
                LOG.warning("Failed to remove shm %s for %s: %s", shm_id, user, err)
            else:
                LOG.info("Removed shm %s for %s", shm_id, user)

    def _cleanup_instance_shm(self):
        for user in (self.ograc_user, self.ogmgr_user):
            self._cleanup_sysv_shm_for_user(user)
            safe_remove(os.path.join("/dev/shm", user))

    def _cleanup_override(self):
        """override 模式下的清理。"""
        LOG.info("Cleaning up override resources")
        if self.ograc_in_container == "0":
            self._stop_systemd_timers()
        safe_remove(os.path.join(self.paths.common_dir, "data"))
        safe_remove(os.path.join(self.paths.common_dir, "socket"))
        safe_remove(self.paths.common_config_dir)
        self._cleanup_instance_shm()

        for user in (self.ograc_user, self.ogmgr_user):
            exec_popen(f"id -u {user} > /dev/null 2>&1 && userdel -rf {user}")

        exec_popen(f"groupdel -f {self.ograc_common_group} > /dev/null 2>&1")

        safe_remove(os.path.join("/etc/systemd/system", self.paths.daemon_timer_unit))
        safe_remove(os.path.join("/etc/systemd/system", self.paths.daemon_service_unit))
        safe_remove(os.path.join("/etc/systemd/system", self.paths.logs_timer_unit))
        safe_remove(os.path.join("/etc/systemd/system", self.paths.logs_service_unit))
        safe_remove("/usr/local/bin/show")
        exec_popen("systemctl daemon-reload")
        self._remove_instance_home()

    def _remove_instance_home(self):
        real_home = os.path.realpath(self.paths.ograc_home)
        if not os.path.isdir(real_home):
            return

        protected_paths = {
            "/", "/opt", "/home", "/usr", "/var", "/tmp", "/mnt", "/mnt/dbdata",
        }
        if real_home in protected_paths:
            LOG.warning("Skip removing protected ograc_home: %s", real_home)
            return

        if len([part for part in real_home.split(os.sep) if part]) < 2:
            LOG.warning("Skip removing shallow ograc_home: %s", real_home)
            return

        action_dir = os.path.realpath(self.paths.action_dir)
        if not action_dir.startswith(real_home + os.sep):
            LOG.warning("Skip removing unexpected ograc_home: %s", real_home)
            return

        quoted_home = shlex.quote(real_home)
        remover_cmd = f"sleep 1; rm -rf -- {quoted_home}"
        try:
            with open(os.devnull, "wb") as devnull:
                subprocess.Popen(
                    ["/bin/bash", "-c", remover_cmd],
                    cwd="/",
                    stdin=devnull,
                    stdout=devnull,
                    stderr=devnull,
                    start_new_session=True,
                )
        except OSError as err:
            LOG.warning("Failed to schedule ograc_home removal %s: %s", real_home, err)
            return
        LOG.info("Scheduled removal of current instance ograc_home: %s", real_home)


_KNOWN_INSTALL_TYPES = {"override", "reserve"}


def _parse_install_args(args):
    """
    兼容多种调用约定，正确拆分 (install_type, config_file)。

      appctl.sh pre_install override config.json  → ("override", "config.json")
      appctl.sh pre_install override              → ("override", "")
      appctl.sh install config_params.json        → ("override", "config_params.json")
      appctl.sh pre_install                       → ("override", "")
    """
    if len(args) >= 2:
        return args[0], args[1]
    if len(args) == 1:
        if args[0] in _KNOWN_INSTALL_TYPES:
            return args[0], ""
        return "override", args[0]
    return "override", ""


def _parse_uninstall_args(args):
    """
    兼容多种调用约定，正确拆分 (uninstall_type, force_type)。

      appctl.sh uninstall override force  → ("override", "force")
      appctl.sh uninstall override        → ("override", "")
      appctl.sh uninstall                 → ("override", "")
    """
    if len(args) >= 2:
        return args[0], args[1]
    if len(args) == 1:
        if args[0] in _KNOWN_INSTALL_TYPES:
            return args[0], ""
        return "override", args[0]
    return "override", ""


def main():
    if len(sys.argv) < 2:
        print("Usage: ograc_deploy.py <action> [args...]")
        sys.exit(1)

    action = sys.argv[1]
    args = sys.argv[2:]

    deployer = OgracDeploy()

    action_map = {
        "pre_install": lambda: deployer.pre_install(*_parse_install_args(args)),
        "install": lambda: deployer.install(*_parse_install_args(args)),
        "start": lambda: deployer.start(args[0] if args else ""),
        "stop": lambda: deployer.stop(),
        "uninstall": lambda: deployer.uninstall(*_parse_uninstall_args(args)),
        "check_status": lambda: deployer.check_status(),
        "backup": lambda: deployer.backup(),
        "init_container": lambda: deployer.init_container(),
        "certificate": lambda: deployer.certificate(*args),
        "config_opt": lambda: deployer.config_opt(*args),
        "clear_upgrade_backup": lambda: deployer.clear_upgrade_backup(),
        "pre_upgrade": lambda: _run_upgrade_action("pre_upgrade", args),
        "upgrade": lambda: _run_upgrade_action("upgrade", args),
        "upgrade_commit": lambda: _run_upgrade_action("upgrade_commit", args),
        "rollback": lambda: _run_upgrade_action("rollback", args),
        "check_point": lambda: _run_upgrade_action("check_point", args),
    }

    handler = action_map.get(action)
    if handler is None:
        print(f"Unknown action: {action}")
        sys.exit(1)

    try:
        ret = handler()
        sys.exit(ret or 0)
    except Exception as e:
        LOG.error("Action %s failed: %s", action, str(e))
        sys.exit(1)


def _run_upgrade_action(action, args):
    """委托升级相关操作到 ograc_upgrade.py。"""
    upgrade_script = os.path.join(CUR_DIR, "upgrade", "ograc_upgrade.py")
    cmd = f"python3 {upgrade_script} {action} " + " ".join(args)
    ret, _, stderr = exec_popen(cmd, timeout=7200)
    if ret != 0:
        LOG.error("%s failed: %s", action, stderr)
    return ret


if __name__ == "__main__":
    main()
