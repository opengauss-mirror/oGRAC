"""
CMS 部署编排器

主入口由 appctl.sh 调用，替代原 appctl.sh 中的大量 shell 逻辑：
  - 所有路径从 config.py 读取（路径解耦）
  - 重复代码已归一到 utils.py
  - 清晰的 Python 错误处理

用法:
    python3 cms_deploy.py <action> [args...]

支持的 action:
    start, stop, pre_install, install, uninstall,
    check_status, backup, restore, init_container,
    pre_upgrade, upgrade_backup, upgrade, rollback, post_upgrade
"""

import os
import sys
import json
import shutil

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
if CUR_DIR not in sys.path:
    sys.path.insert(0, CUR_DIR)

from config import cfg, get_config
from log_config import get_logger
from utils import (
    exec_popen, run_cmd, run_as_user, run_python_as_user, CommandError,
    check_backup_files, check_rollback_files, FileCheckError,
    CGroupManager, IPTablesManager, ProcessManager,
    ensure_dir, ensure_file, copy_tree, safe_remove,
    read_version, get_version_major,
)

LOGGER = get_logger()


class CmsDeploy:
    """
    CMS 部署编排器。

    替代原 appctl.sh 中 802 行 shell 代码，包括：
      - cgroup 管理
      - iptables 管理
      - 用户权限管理
      - 升级 / 回滚 / 备份的编排逻辑
      - 调用 cms_ctl.py（原 cmsctl.py）执行具体操作
    """

    def __init__(self):
        self._cfg = get_config()
        self.paths = self._cfg.paths
        self.deploy = self._cfg.deploy
        self.timeout = self._cfg.timeout

        self.ograc_user = self.deploy.ograc_user
        self.ograc_group = self.deploy.ograc_group
        self.user_and_group = f"{self.ograc_user}:{self.ograc_group}"
        self.deploy_mode = self.deploy.deploy_mode
        self.ograc_in_container = self.deploy.ograc_in_container

        self.storage_share_fs = self.deploy.storage_share_fs
        self.storage_archive_fs = self.deploy.storage_archive_fs
        self.cluster_name = self.deploy.cluster_name
        self.d_user = self._parse_deploy_user()

        self.cgroup = CGroupManager(
            self.paths.cgroup_memory_path,
            self.paths.cgroup_default_mem_size_gb,
        )

        self.log_file = self.paths.cms_deploy_log

    def _parse_deploy_user(self):
        """解析 deploy_user 中的用户名（格式 group:user）"""
        raw = self.deploy.get("deploy_user", "")
        if ":" in raw:
            return raw.split(":")[1]
        return raw


    def _run_cms_ctl(self, action, *extra_args):
        """以 ograc 用户身份调用 cms_ctl.py（结构化参数，按操作超时）"""
        script = os.path.join(CUR_DIR, "cms_ctl.py")
        args = [action] + [str(a) for a in extra_args]
        op_timeout = self.timeout.get(action)
        ret, stdout, stderr = run_python_as_user(
            script, args, self.ograc_user,
            log_file=self.log_file, timeout=op_timeout,
        )
        if ret != 0:
            LOGGER.error(f"cms_ctl.py {action} failed (rc={ret}): {stdout} {stderr}")
            raise CommandError(f"python3 cms_ctl.py {' '.join(args)}", ret, stdout, stderr)
        return stdout

    def _ensure_cms_home(self):
        """确保 CMS 主目录结构存在"""
        ensure_dir(self.paths.cms_home, 0o750, self.user_and_group)
        ensure_dir(self.paths.cms_cfg_dir, 0o750, self.user_and_group)
        ensure_dir(self.paths.cms_log_dir, 0o750, self.user_and_group)
        ensure_file(self.log_file, 0o640, self.user_and_group)

    def _check_old_install(self):
        """检查是否已有 RPM 安装"""
        if os.path.isfile(self.paths.rpm_flag):
            return
        if os.path.isdir(self.paths.cms_service_dir):
            raise RuntimeError(f"CMS already installed in {self.paths.cms_home}")
        if os.path.exists(self.paths.cms_home):
            run_cmd(f"chmod 750 -R {self.paths.cms_home}")
        if os.path.exists(self.paths.cms_log_dir):
            run_cmd(f"chmod 750 -R {self.paths.cms_log_dir}")
            run_cmd(f"find {self.paths.cms_log_dir} -type f | xargs chmod 640")

    def _chown_mod_scripts(self):
        """设置脚本权限"""
        LOGGER.info(f"Setting script permissions for user: {self.ograc_user}")
        run_cmd(
            f"chown -h {self.user_and_group} {CUR_DIR}/*.py {CUR_DIR}/appctl.sh 2>/dev/null; "
            f"chmod 400 {CUR_DIR}/*.py {CUR_DIR}/appctl.sh 2>/dev/null; "
            f"chmod 500 {CUR_DIR}/cms_daemon.py {CUR_DIR}/appctl.sh 2>/dev/null",
            "failed to set script permissions",
        )

    def _ensure_user_profile_writable(self):
        """确保 ograc 用户的 .bashrc 存在且可写（以 root 身份修正 ownership）"""
        import pwd as _pwd
        try:
            home = _pwd.getpwnam(self.ograc_user).pw_dir
        except KeyError:
            LOGGER.warning("User %s not found, skip profile fix", self.ograc_user)
            return
        bashrc = os.path.join(home, ".bashrc")
        if not os.path.exists(bashrc):
            with open(bashrc, "w") as f:
                f.write("")
        run_cmd(f"chown {self.user_and_group} {bashrc}", "failed to chown .bashrc")
        os.chmod(bashrc, 0o644)

    def _copy_cms_scripts(self):
        """复制 CMS 脚本到安装目录（源与目标相同时跳过）"""
        dst = self.paths.cms_scripts
        if os.path.realpath(CUR_DIR) == os.path.realpath(dst):
            LOGGER.info("CMS scripts already in install path, skip copy")
            return
        LOGGER.info("Copying CMS scripts from %s to %s", CUR_DIR, dst)
        if os.path.isdir(dst):
            shutil.rmtree(dst)
        os.makedirs(dst, mode=0o755, exist_ok=True)
        run_cmd(f"cp -arf {CUR_DIR}/* {dst}/")


    def _read_link_type(self):
        """从 deploy_param.json 读取 link_type（替代 awk 手工解析）"""
        return self.deploy.get("link_type", "")

    def _read_deploy_mode_from_backup(self, backup_path):
        """从备份目录的 deploy_param.json 读取 deploy_mode"""
        bak_config = os.path.join(backup_path, "config", "deploy_param.json")
        if os.path.exists(bak_config):
            try:
                with open(bak_config, encoding="utf-8") as f:
                    return json.load(f).get("deploy_mode", "")
            except (json.JSONDecodeError, OSError):
                pass
        return ""

    def _update_cms_service(self, link_type):
        """更新 CMS 服务文件（bin/lib）"""
        LOGGER.info(f"Updating CMS service files in {self.paths.cms_service_dir}")
        pkg = self.paths.cms_pkg_dir

        for target in (self.paths.cms_service_dir, os.path.join(self.paths.ograc_app_home, "server")):
            run_cmd(f"rm -rf {target}/*")
            run_cmd(
                f"cp -arf {pkg}/add-ons {pkg}/admin {pkg}/bin "
                f"{pkg}/cfg {pkg}/lib {pkg}/package.xml {target}"
            )

        if self.deploy_mode in ("file", "dss"):
            return

        addons = os.path.join(self.paths.cms_service_dir, "add-ons")
        if link_type == "1":
            run_cmd(f"cp -arf {addons}/mlnx/lib* {addons}/")
        elif link_type == "0":
            run_cmd(f"cp -arf {addons}/nomlnx/lib* {addons}/")
        else:
            run_cmd(f"cp -arf {addons}/1823/lib* {addons}/")
        run_cmd(f"cp -arf {addons}/kmc_shared/lib* {addons}/")

    def _chown_mod_cms_service(self):
        """设置 CMS 服务文件权限"""
        LOGGER.info("Setting CMS service file permissions")
        for base_dir, sub_dir in [
            (self.paths.cms_home, "service"),
            (self.paths.ograc_app_home, "server"),
        ]:
            target = os.path.join(base_dir, sub_dir) if sub_dir != "service" else self.paths.cms_service_dir
            run_cmd(f"chown -hR {self.user_and_group} {base_dir}")
            run_cmd(f"chmod -R 700 {target}")
            run_cmd(f"find {target}/add-ons -type f | xargs chmod 500")
            run_cmd(f"find {target}/admin -type f | xargs chmod 400")
            run_cmd(f"find {target}/bin -type f | xargs chmod 500")
            run_cmd(f"find {target}/lib -type f | xargs chmod 500")
            run_cmd(f"find {target}/cfg -type f | xargs chmod 400")
            pkg_xml = os.path.join(target, "package.xml")
            if os.path.exists(pkg_xml):
                run_cmd(f"chmod 400 {pkg_xml}")

        if self.deploy_mode == "dss":
            run_cmd(f'setcap CAP_SYS_RAWIO+ep "{self.paths.cms_service_dir}/bin/cms"')

    def _update_cms_config_upgrade(self, deploy_mode_backup):
        """升级时更新 CMS 配置"""
        self._run_cms_ctl("upgrade")

    def _update_cms_gcc_file(self, deploy_mode_backup):
        """升级时更新 GCC 文件（仅在 backup 模式变更时触发）"""
        LOGGER.info("No GCC file update needed")

    def _record_cms_info(self, backup_dir):
        """记录升级前的 CMS 文件信息"""
        LOGGER.info("Recording CMS module info before upgrade")
        cms_bak = os.path.join(backup_dir, "cms")
        os.makedirs(cms_bak, mode=0o750, exist_ok=True)

        run_cmd(f"tree -afis {self.paths.cms_home} >> {cms_bak}/cms_home_files_list.txt")
        run_cmd(f"tree -afis {self.paths.cms_scripts} >> {cms_bak}/cms_scripts_files_list.txt")

        with open(os.path.join(cms_bak, "backup.bak"), "a") as f:
            f.write("cms backup information for upgrade\n")
            ret, time_str, _ = exec_popen("date")
            f.write(f"time: {time_str}\n")
            f.write(f"deploy_user: {self.user_and_group}\n")
            ret, size_str, _ = exec_popen(f"du -sh {self.paths.cms_home}")
            f.write(f"cms_home: total_size={size_str}\n")
            ret, size_str, _ = exec_popen(f"du -sh {self.paths.cms_scripts}")
            f.write(f"cms_scripts: total_size={size_str}\n")


    def _check_cms_node_and_res_list(self):
        """检查 CMS 节点和资源列表"""
        LOGGER.info("Checking CMS node and resource list")
        base_cmd = "source ~/.bashrc && cms"

        ret, stdout, _ = run_as_user(f"{base_cmd} node -list", self.ograc_user)
        if ret != 0:
            raise RuntimeError("Failed to query cms node -list")
        if "node0" not in stdout:
            raise RuntimeError("node0 not found in CMS node list")
        if "node1" not in stdout:
            raise RuntimeError("node1 not found in CMS node list")

        ret, stdout, _ = run_as_user(f"{base_cmd} res -list", self.ograc_user)
        if ret != 0:
            raise RuntimeError("Failed to query cms res -list")
        if "db" not in stdout:
            raise RuntimeError("resource not found in CMS res list")


    def action_start(self):
        """启动 CMS"""
        LOGGER.info("========== START CMS ==========")
        self.cgroup.setup()
        IPTablesManager.accept(self.paths.cms_ini)
        ProcessManager.ensure_shm_dir(self.paths.shm_home, self.user_and_group)
        ProcessManager.clear_shm(self.paths.shm_home, self.paths.instance.shm_pattern)
        self._run_cms_ctl("start")
        LOGGER.info("========== START CMS DONE ==========")

    def action_stop(self):
        """停止 CMS"""
        LOGGER.info("========== STOP CMS ==========")
        self._run_cms_ctl("stop")
        IPTablesManager.delete(self.paths.cms_ini)
        LOGGER.info("========== STOP CMS DONE ==========")

    def action_pre_install(self, install_type=""):
        """预安装"""
        LOGGER.info("========== PRE_INSTALL CMS ==========")
        if install_type == "reserve":
            update_cfg = os.path.join(CUR_DIR, "..", "compat", "update_config.py")
            run_python_as_user(
                update_cfg,
                ["-c", "cms", "-a", "add", "-k", "cms_reserve", "-v", "cms"],
                self.ograc_user,
            )
        self._check_old_install()
        self._chown_mod_scripts()
        self._run_cms_ctl("pre_install", install_type)
        LOGGER.info("========== PRE_INSTALL CMS DONE ==========")

    def _prepare_gcc_device(self):
        """以 root 身份准备 GCC 设备权限（仅 DSS 模式 + 非容器场景）"""
        if self.ograc_in_container != "0":
            return
        gcc_home = self._cfg.deploy.get("gcc_home", "")
        if not gcc_home:
            return
        if self.deploy_mode == "dss":
            node_id = str(self.deploy.node_id)
            LOGGER.info("Preparing GCC device %s as root on node %s", gcc_home, node_id)
            if node_id == "0":
                run_cmd(f"dd if=/dev/zero of={gcc_home} bs=1M count=1025",
                        f"failed to zero gcc device {gcc_home}")
            run_cmd(f"chmod 600 {gcc_home}")
            run_cmd(f"chown {self.user_and_group} {gcc_home}")
        elif self.deploy_mode == "file":
            run_cmd(f"chown {self.user_and_group} {gcc_home} 2>/dev/null || true")

    def _patch_cms_rpath(self):
        """将实例库路径嵌入 cms binary 的 RUNPATH，解决 setcap 后 ld.so 忽略 LD_LIBRARY_PATH 的问题。

        Linux 安全机制：具有 file capabilities 的二进制文件，动态链接器会忽略 LD_LIBRARY_PATH，
        但仍遵守 ELF 自身的 DT_RUNPATH。用 patchelf 将实例的 lib/add-ons 写入二进制，
        不修改任何系统文件、不影响全局链接顺序、多实例互不干扰。
        注意：patchelf 会清除已有 capabilities，因此必须在 setcap 之前调用。
        """
        cms_bin = os.path.join(self.paths.cms_service_dir, "bin", "cms")
        lib_dir = os.path.join(self.paths.cms_service_dir, "lib")
        addons_dir = os.path.join(self.paths.cms_service_dir, "add-ons")
        rpath = f"{lib_dir}:{addons_dir}"

        ret, current_rpath, _ = exec_popen(f'patchelf --print-rpath "{cms_bin}" 2>/dev/null')
        if ret != 0:
            LOGGER.warning("patchelf not available, trying chrpath")
            ret2, _, _ = exec_popen(f'chrpath -r "{rpath}" "{cms_bin}"')
            if ret2 != 0:
                raise RuntimeError(
                    "patchelf/chrpath not found. DSS mode requires one of them to embed "
                    "library paths into the cms binary (setcap makes LD_LIBRARY_PATH ignored). "
                    "Install patchelf: yum install -y patchelf"
                )
            LOGGER.info("Set cms RPATH via chrpath: %s", rpath)
            return

        current_rpath = current_rpath.strip()
        if lib_dir in current_rpath and addons_dir in current_rpath:
            LOGGER.info("cms RPATH already contains required paths, skip patchelf")
            return

        run_cmd(
            f'patchelf --set-rpath "{rpath}" "{cms_bin}"',
            "failed to set RPATH on cms binary",
        )
        LOGGER.info("Set cms RPATH: %s", rpath)

    def _get_cms_install_step(self):
        try:
            return int(self._cfg.deploy.get("install_step", 0) or 0)
        except (TypeError, ValueError):
            return 0

    def action_install(self, install_type=""):
        """安装 CMS"""
        LOGGER.info("========== INSTALL CMS ==========")
        if (self.ograc_in_container == "0"
                and self.deploy_mode != "dss"):
            share_path = self.paths.share_path(self.storage_share_fs)
            run_cmd(f"chown {self.user_and_group} {share_path}")

        if not os.path.isfile(self.paths.rpm_flag):
            self._copy_cms_scripts()

        self._ensure_user_profile_writable()
        cms_install_step = self._get_cms_install_step()
        if cms_install_step >= 2:
            LOGGER.info(
                "CMS install_step=%s, skip root-side GCC prepare to keep install reentrant",
                cms_install_step,
            )
        else:
            self._prepare_gcc_device()

        if self.deploy_mode == "dss":
            # DSS 模式分三步，与旧代码 start_cms.sh install_cms() 保持一致：
            #   1. setup_files: 以 ograc 用户复制 cms binary 及配置
            #   2. setcap:      root 阶段对 cms binary 设置 CAP_SYS_RAWIO
            #   3. setup_gcc:   以 ograc 用户执行 gcc -reset 和 node -add
            # 旧代码执行顺序：sudo setcap → dd → gcc-reset → node-add
            # 若颠倒为 gcc-reset/node-add 先于 setcap，cms binary 缺少 CAP_SYS_RAWIO，
            # cm_dl_getowner(LUN) 返回非 OG_INVALID_ID64，node -add 误判为有 server
            # 在运行，转而走 UDS 路径，因 UDS 文件不存在而报 errno 2。
            self._run_cms_ctl("setup_files")
            self._patch_cms_rpath()
            run_cmd(f'setcap CAP_SYS_RAWIO+ep "{self.paths.cms_service_dir}/bin/cms"')
            self._run_cms_ctl("setup_gcc")
        else:
            self._run_cms_ctl("install")

        if install_type == "reserve":
            update_cfg = os.path.join(CUR_DIR, "..", "compat", "update_config.py")
            run_python_as_user(
                update_cfg,
                ["--component=cms_ini", "--action=update",
                 "--key=_DISK_DETECT_FILE", "--value=gcc_file_detect_disk,"],
                self.ograc_user,
            )
        LOGGER.info("========== INSTALL CMS DONE ==========")

    def action_uninstall(self, uninstall_type="", force_uninstall=""):
        """卸载 CMS"""
        LOGGER.info("========== UNINSTALL CMS ==========")
        self._run_cms_ctl("uninstall", uninstall_type, force_uninstall)
        self.cgroup.clean()
        LOGGER.info("========== UNINSTALL CMS DONE ==========")

    def action_check_status(self):
        """检查状态"""
        self._run_cms_ctl("check_status")

    def action_backup(self):
        """备份"""
        self._run_cms_ctl("backup")

    def action_restore(self):
        """恢复"""
        LOGGER.info("CMS restore not implemented via cms_ctl")

    def action_init_container(self):
        """容器初始化 —— 替代 init_container.sh，包含配置修改 + cms_ctl"""
        LOGGER.info("========== INIT CONTAINER CMS ==========")
        from cms_container_init import CmsContainerInit
        init = CmsContainerInit()
        init.run()
        LOGGER.info("========== INIT CONTAINER CMS DONE ==========")

    def action_pre_upgrade(self):
        """升级前检查"""
        LOGGER.info("========== PRE_UPGRADE CMS ==========")
        version_first = get_version_major(self.paths.versions_yml)
        ograc_user = self.d_user if version_first == 2 else self.ograc_user

        self._chown_mod_scripts()

        if not os.path.isdir(os.path.join(self.paths.cms_home, "service")):
            raise RuntimeError("CMS service directory not found, CMS may not be installed")

        if self.deploy_mode == "file":
            gcc_dir = os.path.join(
                self.paths.share_path(self.storage_share_fs), "gcc_home"
            )
            if not os.path.isdir(gcc_dir):
                raise RuntimeError(f"GCC home not found: {gcc_dir}")

        ret, stdout, _ = run_as_user("source ~/.bashrc && cms stat -server", ograc_user)
        ret2, stdout2, _ = exec_popen(
            f"ps -fu {ograc_user} | grep 'cms server -start' | grep -vE '(grep|defunct)' | wc -l"
        )
        if ret2 == 0 and stdout2.strip() != "1":
            raise RuntimeError("CMS process not running, start it before pre_upgrade")

        self._check_cms_node_and_res_list()
        LOGGER.info("========== PRE_UPGRADE CMS DONE ==========")

    def action_upgrade_backup(self, backup_path):
        """升级备份"""
        LOGGER.info("========== UPGRADE_BACKUP CMS ==========")
        version_first = get_version_major(self.paths.versions_yml)
        ograc_user = self.d_user if version_first == 2 else self.ograc_user

        ret, owner, _ = exec_popen(f"stat -c %U {self.paths.cms_home}")
        if ret == 0 and owner.strip() != ograc_user:
            raise RuntimeError("Upgrade user differs from installed user")

        cms_bak = os.path.join(backup_path, "cms")
        if os.path.isdir(cms_bak):
            raise RuntimeError(f"Backup dir already exists: {cms_bak}")

        os.makedirs(cms_bak, mode=0o750)

        home_bak = os.path.join(cms_bak, "cms_home")
        os.makedirs(home_bak, mode=0o750)
        for item in os.listdir(self.paths.cms_home):
            if item == "log":
                continue
            src = os.path.join(self.paths.cms_home, item)
            run_cmd(f"cp -arf {src} {home_bak}/")

        scripts_bak = os.path.join(cms_bak, "cms_scripts")
        os.makedirs(scripts_bak, mode=0o750)
        run_cmd(f"cp -arf {self.paths.cms_scripts}/* {scripts_bak}/")

        self._record_cms_info(backup_path)

        check_backup_files(
            f"{cms_bak}/cms_home_files_list.txt", home_bak, self.paths.cms_home
        )
        check_backup_files(
            f"{cms_bak}/cms_scripts_files_list.txt", scripts_bak, self.paths.cms_scripts
        )
        LOGGER.info("========== UPGRADE_BACKUP CMS DONE ==========")

    def action_upgrade(self, upgrade_type="", backup_path=""):
        """升级 CMS"""
        LOGGER.info("========== UPGRADE CMS ==========")
        link_type = self._read_link_type()
        deploy_mode_backup = self._read_deploy_mode_from_backup(backup_path)

        self._update_cms_service(link_type)
        self._chown_mod_cms_service()
        self._update_cms_config_upgrade(deploy_mode_backup)

        if os.path.realpath(CUR_DIR) != os.path.realpath(self.paths.cms_scripts):
            run_cmd(f"rm -rf {self.paths.cms_scripts}/*")
            run_cmd(f"cp -arf {CUR_DIR}/* {self.paths.cms_scripts}/")

        self._update_cms_gcc_file(deploy_mode_backup)

        for tmp_file in self.paths.cms_tmp_files:
            safe_remove(tmp_file)
        import glob as g
        for f in g.glob(os.path.join(self.paths.cms_home, "ograc.ogd.cms*")):
            safe_remove(f)

        update_cfg = os.path.join(CUR_DIR, "..", "compat", "update_config.py")
        run_python_as_user(
            update_cfg,
            ["--component=cms_ini", "--action=update",
             "--key=_DISK_DETECT_FILE", "--value=gcc_file_detect_disk,"],
            self.ograc_user,
        )
        LOGGER.info("========== UPGRADE CMS DONE ==========")

    def action_rollback(self, rollback_type="", backup_path=""):
        """回滚 CMS"""
        LOGGER.info("========== ROLLBACK CMS ==========")

        versions_file = os.path.join(CUR_DIR, "../../versions.yml")
        version = read_version(versions_file)

        cms_bak = os.path.join(backup_path, "cms")
        if not os.path.isdir(cms_bak):
            raise RuntimeError(f"Backup dir not found: {cms_bak}")

        home_bak = os.path.join(cms_bak, "cms_home")
        if not os.path.isdir(home_bak):
            raise RuntimeError(f"CMS home backup not found: {home_bak}")

        LOGGER.info(f"Rolling back CMS from {backup_path}, version={version}")

        for item in os.listdir(self.paths.cms_home):
            if item == "log":
                continue
            safe_remove(os.path.join(self.paths.cms_home, item))
        run_cmd(f"cp -arf {home_bak}/* {self.paths.cms_home}/")

        scripts_bak = os.path.join(cms_bak, "cms_scripts")
        if not os.path.isdir(scripts_bak):
            raise RuntimeError(f"CMS scripts backup not found: {scripts_bak}")
        run_cmd(f"rm -rf {self.paths.cms_scripts}/*")
        run_cmd(f"cp -arf {scripts_bak}/* {self.paths.cms_scripts}/")

        check_rollback_files(
            f"{cms_bak}/cms_home_files_list.txt", home_bak, self.paths.cms_home
        )
        check_rollback_files(
            f"{cms_bak}/cms_scripts_files_list.txt", scripts_bak, self.paths.cms_scripts
        )
        LOGGER.info("========== ROLLBACK CMS DONE ==========")

    def action_post_upgrade(self):
        """升级后检查"""
        LOGGER.info("========== POST_UPGRADE CMS ==========")

        if not os.listdir(self.paths.cms_service_dir):
            raise RuntimeError("CMS service directory is empty after upgrade")

        if not os.listdir(self.paths.cms_scripts):
            raise RuntimeError("CMS scripts directory is empty after upgrade")

        if self.deploy_mode == "file":
            gcc_dir = os.path.join(
                self.paths.share_path(self.storage_share_fs), "gcc_home"
            )
            if not os.path.isdir(gcc_dir):
                raise RuntimeError(f"GCC home not found after upgrade: {gcc_dir}")

        ret, stdout, _ = run_as_user(
            "source ~/.bashrc && cms stat -server", self.ograc_user
        )
        ret2, count_str, _ = exec_popen(
            f"ps -fu {self.ograc_user} | grep 'cms server -start' | grep -vE '(grep|defunct)' | wc -l"
        )
        if ret2 == 0 and count_str.strip() != "1":
            raise RuntimeError("CMS process is not running after upgrade")

        self._check_cms_node_and_res_list()
        LOGGER.info("========== POST_UPGRADE CMS DONE ==========")



def main():
    if len(sys.argv) < 2:
        print(
            "Usage: python3 cms_deploy.py <action> [args...]\n"
            "Actions: start, stop, pre_install, install, uninstall, check_status,\n"
            "         backup, restore, init_container, pre_upgrade, upgrade_backup,\n"
            "         upgrade, rollback, post_upgrade",
            file=sys.stderr,
        )
        sys.exit(1)

    action = sys.argv[1]
    args = sys.argv[2:]

    deployer = CmsDeploy()
    deployer._ensure_cms_home()

    try:
        if action == "start":
            deployer.action_start()
        elif action == "stop":
            deployer.action_stop()
        elif action == "pre_install":
            install_type = args[0] if args else ""
            deployer.action_pre_install(install_type)
        elif action == "install":
            install_type = args[0] if args else ""
            deployer.action_install(install_type)
        elif action == "uninstall":
            uninstall_type = args[0] if args else ""
            force_uninstall = args[1] if len(args) > 1 else ""
            deployer.action_uninstall(uninstall_type, force_uninstall)
        elif action == "check_status":
            deployer.action_check_status()
        elif action == "backup":
            deployer.action_backup()
        elif action == "restore":
            deployer.action_restore()
        elif action == "init_container":
            deployer.action_init_container()
        elif action == "pre_upgrade":
            deployer.action_pre_upgrade()
        elif action == "upgrade_backup":
            backup_path = args[0] if args else ""
            deployer.action_upgrade_backup(backup_path)
        elif action == "upgrade":
            upgrade_type = args[0] if args else ""
            backup_path = args[1] if len(args) > 1 else ""
            deployer.action_upgrade(upgrade_type, backup_path)
        elif action == "rollback":
            rollback_type = args[0] if args else ""
            backup_path = args[1] if len(args) > 1 else ""
            deployer.action_rollback(rollback_type, backup_path)
        elif action == "post_upgrade":
            deployer.action_post_upgrade()
        else:
            print(f"Unknown action: {action}", file=sys.stderr)
            sys.exit(1)

    except (CommandError, FileCheckError, RuntimeError) as e:
        LOGGER.error(f"Action '{action}' failed: {e}")
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        LOGGER.error(f"Unexpected error in action '{action}': {e}", exc_info=True)
        print(f"UNEXPECTED ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
