#!/usr/bin/env python3
"""CMS core controller."""

import sys
import os
import copy
import json
import grp
import pwd
import re
import shutil
import socket
import stat
import time

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
if CUR_DIR not in sys.path:
    sys.path.insert(0, CUR_DIR)

from config import cfg, get_config
from log_config import get_logger
from utils import exec_popen, run_cmd, CommandError, ProcessManager

sys.dont_write_bytecode = True

LOGGER = get_logger()
FORCE_UNINSTALL = None
CHECK_MAX_TIMES = 7

FILE_MODE_400 = 0o400
FILE_MODE_500 = 0o500
FILE_MODE_600 = 0o600
FILE_MODE_640 = 0o640
DIR_MODE_700 = 0o700
DIR_MODE_750 = 0o750



def _raise_unless_force(msg, exc_type=Exception):
    """Raise on error unless force mode (then log only)."""
    LOGGER.error(msg)
    if FORCE_UNINSTALL != "force":
        raise exc_type(msg)



def check_platform():
    """Check OS platform."""
    import platform
    current_os = platform.system()
    LOGGER.info(f"check current os: {current_os}")
    if current_os != "Linux":
        _raise_unless_force(f"Unsupported platform: {current_os}")


def check_runner():
    """Check script runner matches owner."""
    owner_uid = os.stat(__file__).st_uid
    runner_uid = os.getuid()
    LOGGER.info(f"check runner/owner uid: {runner_uid}/{owner_uid}")

    if owner_uid == 0 and runner_uid != 0:
        _raise_unless_force(f"Root-owned script cannot be run by uid {runner_uid}")
    elif owner_uid != 0:
        if runner_uid == 0:
            _raise_unless_force(f"Non-root script cannot be run by root")
        elif runner_uid != owner_uid:
            _raise_unless_force(f"Owner uid {owner_uid} != runner uid {runner_uid}")


def check_user(user, group):
    """Validate user and group."""
    LOGGER.info(f"check user/group: {user}:{group}")
    try:
        user_info = pwd.getpwnam(user)
    except KeyError:
        _raise_unless_force(f"User does not exist: {user}")
        return
    try:
        group_info = grp.getgrnam(group)
    except KeyError:
        _raise_unless_force(f"Group does not exist: {group}")
        return

    if user_info.pw_gid != group_info.gr_gid:
        _raise_unless_force(f"User {user} does not belong to group {group}")
    if user == "root" or user_info.pw_uid == 0:
        _raise_unless_force("Cannot install to root user")
    if group == "root" or user_info.pw_gid == 0:
        _raise_unless_force("Cannot install to root group")

    runner_uid = os.getuid()
    if runner_uid != 0 and runner_uid != user_info.pw_uid:
        runner = pwd.getpwuid(runner_uid).pw_name
        _raise_unless_force(f"Must run as user {user}, current: {runner}")


def check_path(path_str):
    """Check path validity."""
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 /_-.")
    return all(c in allowed for c in path_str)



def _build_cms_config():
    """Build CMS config dict."""
    _cfg = get_config()
    mes_ssl_switch = _cfg.deploy.get("mes_ssl_switch", "False")

    config = {
        "NODE_ID": 0,
        "GCC_HOME": "",
        "GCC_DIR": "",
        "GCC_TYPE": "",
        "CMS_LOG": _cfg.paths.cms_log_dir,
        "_PORT": 14587,
        "_IP": "",
        "_LOG_LEVEL": 7,
        "_SPLIT_BRAIN": "TRUE",
        "_LOG_MAX_FILE_SIZE": "60M",
        "_DETECT_DISK_TIMEOUT": 100,
        "_DISK_DETECT_FILE": "gcc_file_detect_disk,",
        "_STOP_RERUN_CMS_SCRIPT": os.path.join(_cfg.paths.cms_scripts, "cms_daemon.py"),
        "_EXIT_NUM_COUNT_FILE": os.path.join(_cfg.paths.cms_cfg_dir, "exit_num.txt"),
        "_CMS_NODE_FAULT_THRESHOLD": "6",
        "_CMS_MES_THREAD_NUM": "5",
        "_CMS_MES_MAX_SESSION_NUM": "40",
        "_CMS_MES_MESSAGE_POOL_COUNT": "1",
        "_CMS_MES_MESSAGE_QUEUE_COUNT": "1",
        "_CMS_MES_MESSAGE_BUFF_COUNT": "4096",
        "_CMS_MES_MESSAGE_CHANNEL_NUM": "1",
        "_CMS_GCC_BAK": "",
        "_CLUSTER_ID": 0,
        "_CMS_MES_PIPE_TYPE": "TCP",
        "_CMS_MES_SSL_SWITCH": mes_ssl_switch,
        "_CMS_MES_SSL_KEY_PWD": None,
        "_CMS_MES_SSL_CRT_KEY_PATH": _cfg.paths.certificates_dir,
        "KMC_KEY_FILES": f"({_cfg.paths.primary_keystore}, {_cfg.paths.standby_keystore})",
    }
    return config


GCC_TYPE_MAP = {
    "file": "file",
    "dss": "LUN",
}

USE_DSS = ("dss",)
CLUSTER_SIZE = 2



class CmsCtl:
    """CMS core controller."""

    def __init__(self):
        self._cfg = get_config()
        self.paths = self._cfg.paths
        self.deploy_mode = self._cfg.deploy.deploy_mode

        self.user = self._cfg.deploy.ograc_user
        self.group = self._cfg.deploy.ograc_group

        self.node_id = 0
        self.cluster_id = 0
        self.port = "14587"
        self.ip_addr = ""
        self.ip_cluster = "192.168.86.1;192.168.86.2"
        self.cluster_name = ""
        self.ipv_type = "ipv4"

        self.install_type = "override"
        self.uninstall_type = ""
        self.running_mode = "ogracd_in_cluster"
        self.link_type = "RDMA"
        self.install_step = 0

        self.install_path = self.paths.cms_service_dir
        self.cms_home = self.paths.cms_home
        self.cms_scripts = self.paths.cms_scripts
        self.cms_new_config = self.paths.cms_json
        self.cms_old_config = self.paths.cms_old_config
        self.user_profile = ""
        self.user_home = ""

        self.gcc_home = "/dev/gcc-disk"
        self.gcc_dir = ""
        self.gcc_type = GCC_TYPE_MAP.get(self.deploy_mode, "NFS")
        if os.path.exists(self.paths.youmai_demo):
            self.gcc_type = "NFS"
        self.cms_gcc_bak = "/dev/gcc-disk"

        self.storage_share_fs = ""
        self.storage_archive_fs = ""
        self.storage_metadata_fs = ""
        self.share_logic_ip = ""

        self.use_gss = self.deploy_mode in USE_DSS
        self.mes_type = ""
        self.cluster_uuid = ""

        self.install_config_file = os.path.join(CUR_DIR, "..", "config_params_lun.json")


    def parse_parameters(self, config_file):
        """Load params from JSON config."""
        if not os.path.exists(config_file):
            _raise_unless_force(f"Config file not found: {config_file}")
            return
        try:
            with open(config_file, 'r') as f:
                params = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            _raise_unless_force(f"Failed to read config: {e}")
            return

        self._load_user_config(params)
        self._load_run_config(params)
        self._load_path_config(params)
        self._load_port_config(params)

    def _load_user_config(self, d):
        if "user" in d:
            self.user = d["user"]
        if "group" in d:
            self.group = d["group"]
        if "install_type" in d and self.install_type != "reserve":
            self.install_type = d["install_type"]
        if "install_step" in d:
            self.install_step = d["install_step"]
        if "link_type" in d:
            lt = d["link_type"]
            if lt in ("0", "TCP"):
                self.link_type = "TCP"
            elif lt in ("2", "RDMA_1823"):
                self.link_type = "RDMA_1823"
        if "cluster_name" in d:
            self.cluster_name = d["cluster_name"]
        if "mes_type" in d:
            self.mes_type = self._cfg.deploy.get("mes_type", "TCP")

    def _load_run_config(self, d):
        for key in ("cms_ip", "ip_cluster"):
            if key in d:
                self.ip_cluster = d[key]
        if "node_id" in d:
            self.node_id = int(d["node_id"])
        if "cluster_id" in d:
            self.cluster_id = int(d["cluster_id"])
        if "gcc_type" in d:
            self.gcc_type = d["gcc_type"]
        if "port" in d:
            self.port = d["port"]
        if "ip_addr" in d:
            self.ip_addr = d["ip_addr"]
        if "running_mode" in d:
            self.running_mode = d["running_mode"]
        if "ipv_type" in d:
            self.ipv_type = d["ipv_type"]
        if "share_logic_ip" in d:
            self.share_logic_ip = d["share_logic_ip"]

    def _load_path_config(self, d):
        if "gcc_home" in d:
            self.gcc_home = d["gcc_home"]
        if "storage_share_fs" in d:
            self.storage_share_fs = d["storage_share_fs"]
        if "storage_archive_fs" in d:
            self.storage_archive_fs = d["storage_archive_fs"]
        if "storage_metadata_fs" in d:
            self.storage_metadata_fs = d["storage_metadata_fs"]
        if "user_profile" in d:
            self.user_profile = d["user_profile"]
        if "install_path" in d:
            self.install_path = d["install_path"]
        if "cms_home" in d:
            self.cms_home = d["cms_home"]
        if "user_home" in d:
            self.user_home = d["user_home"]
        if "install_config_file" in d:
            self.install_config_file = d["install_config_file"]
        if "cms_new_config" in d:
            self.cms_new_config = d["cms_new_config"]
        if "cms_gcc_bak" in d:
            self.cms_gcc_bak = d["cms_gcc_bak"]

    def _load_port_config(self, d):
        if "cms_port" in d:
            self.port = d["cms_port"]


    def set_cms_conf(self):
        """Save CMS run config to cms.json."""
        conf = {
            "user": self.user, "group": self.group,
            "node_id": self.node_id, "cluster_id": self.cluster_id,
            "gcc_home": self.gcc_home, "gcc_dir": self.gcc_dir,
            "gcc_type": self.gcc_type, "port": self.port,
            "ip_addr": self.ip_addr, "install_step": self.install_step,
            "user_profile": self.user_profile, "install_path": self.install_path,
            "running_mode": self.running_mode, "cms_home": self.cms_home,
            "user_home": self.user_home, "use_gss": self.use_gss,
            "storage_share_fs": self.storage_share_fs,
            "storage_archive_fs": self.storage_archive_fs,
            "install_type": self.install_type, "uninstall_type": self.uninstall_type,
            "ipv_type": self.ipv_type, "link_type": self.link_type,
            "cms_new_config": self.cms_new_config, "ip_cluster": self.ip_cluster,
            "install_config_file": self.install_config_file,
            "share_logic_ip": self.share_logic_ip,
            "cluster_name": self.cluster_name,
            "cms_gcc_bak": self.cms_gcc_bak, "mes_type": self.mes_type,
        }
        LOGGER.info(f"Saving CMS config to {self.cms_new_config}")
        try:
            with os.fdopen(
                os.open(self.cms_new_config, os.O_RDWR | os.O_CREAT | os.O_TRUNC,
                         stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP), "w"
            ) as f:
                json.dump(conf, f, indent=2)
        except OSError as e:
            _raise_unless_force(f"Failed to write config: {e}")

    def set_conf(self, config, filename):
        """Write INI-style config (cms.ini etc)."""
        conf_file = os.path.join(self.cms_home, "cfg", filename)
        run_cmd(f"echo >> {conf_file}", f"failed to write {filename}")

        config["_IP"] = self.ip_addr
        config["_PORT"] = self.port
        config["NODE_ID"] = self.node_id
        config["_CLUSTER_ID"] = self.cluster_id
        config["GCC_HOME"] = self.gcc_home
        config["GCC_DIR"] = self.gcc_dir
        config["FS_NAME"] = self.storage_share_fs
        config["GCC_TYPE"] = self.gcc_type
        config["_CMS_GCC_BAK"] = self.cms_gcc_bak

        params = copy.deepcopy(config)
        if "GCC_TYPE" in params:
            params["GCC_DIR"] = params["GCC_HOME"]
            if self.deploy_mode not in USE_DSS:
                params["GCC_HOME"] = os.path.join(params["GCC_HOME"], "gcc_file")

        self._clean_old_conf(list(params.keys()), conf_file)
        self._set_new_conf(params, conf_file)

    def set_cluster_conf(self):
        """Write cluster.ini."""
        conf_file = os.path.join(self.cms_home, "cfg", "cluster.ini")
        run_cmd(f"echo >> {conf_file}", f"failed to write cluster.ini")

        size = CLUSTER_SIZE if self.running_mode == "ogracd_in_cluster" else 1
        node_ip = self.ip_cluster.split(";")
        if len(node_ip) == 1:
            node_ip.append("127.0.0.1")

        gcc_home = self.gcc_home
        gcc_dir = self.gcc_dir
        if self.gcc_type not in ("SD", "LUN"):
            gcc_dir = gcc_home
            gcc_home = os.path.join(gcc_home, "gcc_file")

        ld_paths = [
            os.path.join(self.install_path, "lib"),
            os.path.join(self.install_path, "add-ons"),
        ]
        if "LD_LIBRARY_PATH" in os.environ:
            ld_paths.append(os.environ["LD_LIBRARY_PATH"])

        log_file = self.paths.cms_deploy_log
        ograc_home = self.paths.ograc_home
        cms_home = os.path.join(ograc_home, "cms")
        dss_home = os.path.join(ograc_home, "dss")

        params = {
            "GCC_HOME": gcc_home,
            "GCC_DIR": gcc_dir,
            "REPORT_FILE": log_file,
            "STATUS_LOG": os.path.join(self.paths.cms_log_dir, "CmsStatus.log"),
            "LD_LIBRARY_PATH": ":".join(ld_paths),
            "USER_HOME": self.user_home,
            "USE_GSS": self.use_gss,
            "CLUSTER_SIZE": size,
            "NODE_ID": self.node_id,
            "NODE_IP[0]": node_ip[0],
            "NODE_IP[1]": node_ip[1],
            "CMS_PORT[0]": self.port,
            "CMS_PORT[1]": self.port,
            "LSNR_NODE_IP[0]": node_ip[0],
            "LSNR_NODE_IP[1]": node_ip[1],
            "USER": self.user,
            "GROUP": self.group,
            "CMS_HOME": cms_home,
            "DSS_HOME": dss_home,
        }
        self._clean_old_conf(list(params.keys()), conf_file)
        self._set_new_conf(params, conf_file)

    @staticmethod
    def _set_new_conf(param_dict, conf_file):
        cmd = ""
        for key, value in param_dict.items():
            cmd += f"echo '{key} = {value}' >> {conf_file};"
        if cmd:
            cmd += f"chmod 600 {conf_file}"
            run_cmd(cmd, f"failed to write {conf_file}")

    @staticmethod
    def _clean_old_conf(param_list, conf_file):
        cmd = ""
        for param in param_list:
            escaped = param.replace("[", r"\[").replace("]", r"\]")
            cmd += f"sed -i '/^{escaped}/d' {conf_file};"
        if cmd:
            run_cmd(cmd.rstrip(";"), f"failed to clean {conf_file}")


    def _check_ip_valid(self, nodeip):
        """Check IP validity."""
        LOGGER.info(f"check IP: {nodeip}")
        ograc_in_container = self._cfg.deploy.ograc_in_container
        if ograc_in_container == "0":
            try:
                socket.inet_aton(nodeip)
            except socket.error:
                self.ipv_type = "ipv6"
                try:
                    socket.inet_pton(socket.AF_INET6, nodeip)
                except socket.error:
                    _raise_unless_force(f"Invalid IP address: {nodeip}")

        ping_cmd = "ping6" if self.ipv_type == "ipv6" else "ping"
        ret, stdout, stderr = exec_popen(f"{ping_cmd} {nodeip} -i 1 -c 3 | grep ttl | wc -l")
        if ret or stdout.strip() != "3":
            _raise_unless_force(f"Cannot reach IP: {nodeip}")

    def _check_share_logic_ip(self, node_ip):
        """Check NFS logic IP."""
        if self.deploy_mode != "file":
            return
        LOGGER.info(f"check share logic IP: {node_ip}")
        for ping_cmd in ("ping", "ping6"):
            ret, stdout, _ = exec_popen(f"{ping_cmd} {node_ip} -i 1 -c 3 | grep ttl | wc -l")
            if ret == 0 and stdout.strip() == "3":
                return
        _raise_unless_force(f"Cannot reach share logic IP: {node_ip}")

    def _check_port(self, port_value, node_ip):
        """Check port availability."""
        LOGGER.info(f"check port: {port_value}")
        if not port_value:
            _raise_unless_force("Port is empty")
            return
        port = int(port_value)
        if port < 0 or port > 65535:
            _raise_unless_force(f"Invalid port: {port}")
        if port <= 1023:
            _raise_unless_force(f"System reserved port: {port}")

        family = socket.AF_INET6 if self.ipv_type == "ipv6" else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(2)
        try:
            sock.bind((node_ip, port))
        except socket.error as e:
            sock.close()
            if int(e.errno) in (98, 95, 13):
                _raise_unless_force(f"Port {port} is already in use")
            return
        sock.close()

    def check_parameter_install(self):
        """Validate install params."""
        ograc_in_container = self._cfg.deploy.ograc_in_container
        if self.ip_cluster:
            ip_list = self.ip_cluster.split(";")
            self.ip_addr = ip_list[self.node_id]
            for item in re.split(r"[;,]", self.ip_cluster):
                if ograc_in_container == "0":
                    self._check_ip_valid(item)
        else:
            self.ip_addr = "127.0.0.1"

        for ip in self.ip_addr.split(","):
            self._check_port(self.port, ip)

        if ograc_in_container == "0":
            self._check_share_logic_ip(self.share_logic_ip)

        valid_modes = {"ogracd", "ogracd_in_cluster"}
        if self.running_mode not in valid_modes:
            _raise_unless_force(f"Invalid running mode: {self.running_mode}")
        if self.node_id not in (0, 1):
            _raise_unless_force(f"Invalid node_id: {self.node_id}")


    def copy_app_files(self):
        """Copy install files."""
        if not os.path.exists(self.install_path):
            os.makedirs(self.install_path, DIR_MODE_700)

        if not os.path.exists(self.paths.rpm_flag):
            pkg = self.paths.cms_pkg_dir
            cmd = (f"cp -arf {pkg}/add-ons {pkg}/admin {pkg}/bin "
                   f"{pkg}/cfg {pkg}/lib {pkg}/package.xml {self.install_path}")
            run_cmd(cmd, "failed to copy CMS files")

    def change_app_permission(self):
        """Set app file permissions."""
        cmd = f"chmod 700 {self.install_path} -R"
        cmd += f" && find '{self.install_path}'/add-ons -type f | xargs chmod 500"
        cmd += f" && find '{self.install_path}'/admin -type f | xargs chmod 400"
        cmd += f" && find '{self.install_path}'/lib -type f | xargs chmod 500"
        cmd += f" && find '{self.install_path}'/bin -type f | xargs chmod 500"
        cmd += f" && find '{self.install_path}'/cfg -type f | xargs chmod 600"
        pkg_xml = os.path.join(self.install_path, "package.xml")
        if os.path.exists(pkg_xml):
            cmd += f" && chmod 400 '{self.install_path}'/package.xml"
        run_cmd(cmd, "failed to set permissions")

        ograc_in_container = self._cfg.deploy.ograc_in_container
        if ograc_in_container == "0" and (
            self.deploy_mode == "file" or os.path.exists(self.paths.youmai_demo)
        ):
            self._chown_gcc_dirs()

    def _chown_gcc_dirs(self):
        cmd = f'chown {self.user}:{self.group} -hR "{self.gcc_home}"'
        self._check_share_logic_ip(self.share_logic_ip)
        run_cmd(cmd, f"failed to chown gcc dir")

    def export_user_env(self):
        """Export user env vars to .bashrc (after shebang, before interactive guard)."""
        lib_path = (
            f'"{os.path.join(self.install_path, "lib")}"'
            f':"{os.path.join(self.install_path, "add-ons")}"'
        )
        env_lines = [
            f'export CMS_HOME="{self.cms_home}"\n',
            f'export PATH="{os.path.join(self.install_path, "bin")}":$PATH\n',
            f'export GCC_HOME="{self.gcc_home}"\n',
            f"export LD_LIBRARY_PATH={lib_path}:$LD_LIBRARY_PATH\n",
        ]
        try:
            lines = []
            if os.path.isfile(self.user_profile):
                with open(self.user_profile, "r", encoding="utf-8") as f:
                    lines = f.readlines()

            for env_line in env_lines:
                while env_line in lines:
                    lines.remove(env_line)

            insert_pos = 0
            for i, line in enumerate(lines):
                stripped = line.strip()
                if stripped == "" or stripped.startswith("#") or stripped.startswith("#!/"):
                    insert_pos = i + 1
                else:
                    break
            for j, env_line in enumerate(env_lines):
                lines.insert(insert_pos + j, env_line)

            with open(self.user_profile, "w", encoding="utf-8") as f:
                f.writelines(lines)
        except OSError as e:
            _raise_unless_force(f"Failed to export user env: {e}")

    def check_old_install(self):
        """Check if already installed."""
        LOGGER.info("check old install...")
        try:
            pw = pwd.getpwnam(self.user)
            user_home = pw.pw_dir
        except KeyError:
            _raise_unless_force(f"User '{self.user}' does not exist")
            return
        user_home = os.path.realpath(os.path.normpath(user_home))
        if not check_path(user_home):
            _raise_unless_force("Invalid user home directory")
            return
        self.user_profile = os.path.join(user_home, ".bashrc")
        self.user_home = user_home
        self._check_profile()

    def _check_profile(self):
        """Check if .bashrc already has CMS_HOME."""
        if not os.path.isfile(self.user_profile):
            LOGGER.info(".bashrc not found at %s, skipping profile check", self.user_profile)
            return
        try:
            with open(self.user_profile, "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("#"):
                        continue
                    if "export" in line and "CMS_HOME=" in line:
                        _raise_unless_force("CMS has been installed already")
                        return
        except PermissionError:
            LOGGER.warning("Cannot read %s (permission denied), skipping profile check",
                           self.user_profile)
        except OSError as e:
            _raise_unless_force(f"Failed to check profile: {e}")

    def prepare_gccdata_dir(self):
        """Prepare GCC data dir."""
        self._check_share_logic_ip(self.share_logic_ip)
        if (self.deploy_mode == "file" or os.path.exists(self.paths.youmai_demo)):
            if not os.path.exists(self.gcc_home):
                os.makedirs(self.gcc_home, DIR_MODE_700)


    def pre_install(self):
        """Pre-install."""
        check_platform()
        check_runner()
        if self.install_type not in ("override", "reserve"):
            _raise_unless_force("wrong install type")
            return
        if self.install_type != "override":
            LOGGER.info("check install type: reserve cms")
            self.parse_parameters(self.cms_old_config)
            self.__init__()
        else:
            LOGGER.info("check install type: override cms")
            self.parse_parameters(self.install_config_file)
            if self.deploy_mode == "dss":
                LOGGER.info(f"gcc path: {self.gcc_home}")
            else:
                self.gcc_home = self.paths.gcc_home_path("file", self.storage_share_fs)
                self.cms_gcc_bak = self.paths.cms_gcc_bak_path("file", self.storage_archive_fs)
            if os.path.exists(self.paths.youmai_demo):
                self.gcc_home = self.paths.gcc_home_path("file", self.storage_share_fs)
                self.cms_gcc_bak = self.paths.cms_gcc_bak_path("file", self.storage_archive_fs)
            self.gcc_dir = self.gcc_home

        LOGGER.info("===== begin pre_install cms =====")
        check_user(self.user, self.group)
        if self.deploy_mode == "file" and not check_path(self.gcc_home):
            _raise_unless_force("Invalid gcc home directory")
        self.check_parameter_install()
        self.check_old_install()
        self.install_step = 1
        self.set_cms_conf()
        LOGGER.info("===== pre_install cms done =====")

    def _setup_files(self):
        """Copy files, set permissions, generate config (no GCC init)."""
        self.copy_app_files()
        ograc_in_container = self._cfg.deploy.ograc_in_container
        if ograc_in_container == "0":
            self.prepare_gccdata_dir()
        self.export_user_env()
        self.change_app_permission()
        self.set_cluster_conf()
        self.set_conf(_build_cms_config(), "cms.ini")

    def _setup_gcc(self):
        """GCC init + node registration (cms binary must have CAP_SYS_RAWIO before this)."""
        from cms_startup import CmsStartup
        startup = CmsStartup()
        startup.install_cms()
        self.install_step = 2
        self.set_cms_conf()

    def setup_files(self):
        """Copy files and generate config only; no GCC ops. Root calls setcap before setup_gcc."""
        LOGGER.info("===== begin setup_files cms =====")
        if self.install_step == 2:
            LOGGER.info("CMS already installed, skip setup_files")
            return
        if self.install_step == 0:
            _raise_unless_force("Please run pre_install first")
            return
        self._setup_files()
        LOGGER.info("===== setup_files cms done =====")

    def setup_gcc(self):
        """GCC init: gcc -reset + node -add (requires CAP_SYS_RAWIO on cms binary)."""
        LOGGER.info("===== begin setup_gcc cms =====")
        if self.install_step == 2:
            LOGGER.info("CMS already installed")
            return
        self._setup_gcc()
        LOGGER.info("===== setup_gcc cms done =====")

    def install(self):
        """Install CMS (non-DSS or legacy entry; combines setup_files + setup_gcc)."""
        LOGGER.info("===== begin install cms =====")
        if self.install_step == 2:
            LOGGER.info("CMS already installed")
            return
        if self.install_step == 0:
            _raise_unless_force("Please run pre_install first")
            return
        self._setup_files()
        self._setup_gcc()
        LOGGER.info("===== install cms done =====")

    def start(self):
        """Start CMS."""
        LOGGER.info("===== begin start cms =====")
        if self.install_step <= 1:
            _raise_unless_force("Please run install first")
            return
        if ProcessManager.is_running("cms server -start"):
            LOGGER.info("CMS already running")
            return

        from cms_startup import CmsStartup
        startup = CmsStartup()
        startup.start_cms()

        self.install_step = 3
        self.set_cms_conf()
        self._check_start_status()
        LOGGER.info("===== start cms done =====")

    def _check_start_status(self):
        """Check status after start."""
        cmd = (f"source ~/.bashrc && cms stat -server {self.node_id} "
               f"| grep -v NODE_ID | awk '{{print $2}}'")
        for _ in range(300):
            if not ProcessManager.is_running("cms server -start"):
                _raise_unless_force("CMS process stopped unexpectedly")
                return
            try:
                status = run_cmd(cmd, "query server status", FORCE_UNINSTALL)
            except (CommandError, ValueError):
                time.sleep(1)
                continue
            if status.strip() == "TRUE":
                LOGGER.info(f"CMS server status: TRUE")
                break
            time.sleep(1)
        else:
            _raise_unless_force("CMS server status check timeout")

        vcmd = "source ~/.bashrc && cms node -connected | awk '{print $1, $NF}' | grep -v VOTING"
        for _ in range(300):
            if not ProcessManager.is_running("cms server -start"):
                _raise_unless_force("CMS process stopped unexpectedly")
                return
            try:
                output = run_cmd(vcmd, "query voting status", FORCE_UNINSTALL)
            except (CommandError, ValueError):
                time.sleep(1)
                continue
            if not output:
                time.sleep(1)
                continue
            for line in output.strip().split("\n"):
                parts = line.split()
                if len(parts) >= 2 and int(parts[0]) == self.node_id and parts[1] == "FALSE":
                    return
            time.sleep(1)
        else:
            _raise_unless_force("CMS voting status check timeout")

    def check_status(self):
        """Check CMS status."""
        LOGGER.info("===== check cms status =====")
        if self.install_step <= 1:
            _raise_unless_force("CMS not installed")
            return
        cmd = f"source ~/.bashrc && {self.install_path}/bin/cms stat -server 2>&1"
        stdout = run_cmd(cmd, "cannot check CMS status")
        for line in stdout.split("\n")[1:]:
            parts = line.split()
            if parts and int(parts[0].strip()) == self.node_id and "TRUE" in line:
                LOGGER.info("CMS status check passed")
                return
        _raise_unless_force("CMS status check failed")

    def stop(self):
        """Stop CMS."""
        LOGGER.info("===== begin stop cms =====")
        processes = ["cms server", "cms_ctl.py start", "cms_startup.py"]
        for proc in processes:
            ProcessManager.kill_process(proc)
            ProcessManager.ensure_stopped(proc, FORCE_UNINSTALL)
        self.install_step = 2
        self.set_cms_conf()
        LOGGER.info("===== stop cms done =====")

    def uninstall(self):
        """Uninstall CMS."""
        LOGGER.info("===== begin uninstall cms =====")
        ograc_in_container = self._cfg.deploy.ograc_in_container

        if not self.gcc_home:
            if self.deploy_mode == "dss":
                self.gcc_home = os.getenv("GCC_HOME", "")
            else:
                self.gcc_home = self.paths.gcc_home_path("file", self.storage_share_fs)

        if self.node_id == 0:
            self._uninstall_gcc(ograc_in_container)

        self._clean_environment()
        if not os.path.exists(self.paths.rpm_flag):
            self._clean_install_path()

        tmp_cmd = "rm -rf {0}/cms_server.lck {0}/local {0}/gcc_backup {0}/ograc.ctd.cms*".format(
            self.cms_home)
        run_cmd(tmp_cmd, "failed to remove running files", FORCE_UNINSTALL)
        LOGGER.info("===== uninstall cms done =====")

    def _uninstall_gcc(self, ograc_in_container):
        """Uninstall GCC data."""
        if ograc_in_container == "0":
            self._check_share_logic_ip(self.share_logic_ip)

        if self.deploy_mode == "file" or os.path.exists(self.paths.youmai_demo):
            share_path = self.paths.share_path(self.storage_share_fs)
            archive_path = self.paths.archive_path(self.storage_archive_fs)
            versions = os.path.join(share_path, "versions.yml")
            gcc_bak = os.path.join(archive_path, "gcc_backup")
            str_cmd = f"rm -rf {self.gcc_home} && rm -rf {versions} && rm -rf {gcc_bak}"
            ret, _, _ = exec_popen(f"timeout 10 ls {self.gcc_home}")
            if ret == 0:
                run_cmd(str_cmd, "failed to remove gcc home", FORCE_UNINSTALL)
        elif self.deploy_mode in USE_DSS:
            str_cmd = f"dd if=/dev/zero of={self.gcc_home} bs=1M count=1024 conv=notrunc"
            run_cmd(str_cmd, "failed to zero gcc", FORCE_UNINSTALL)

    def _clean_install_path(self):
        """Clean install path."""
        LOGGER.info("cleaning install path...")
        for path in (
            self.install_path,
            os.path.join(self.cms_home, "cfg"),
        ):
            if os.path.exists(path):
                shutil.rmtree(path)

    def _clean_environment(self):
        """Clean user env vars."""
        LOGGER.info("cleaning user environment variables...")
        if not self.user_profile:
            self.user_profile = os.path.join("/home", self.user, ".bashrc")
        if not os.path.exists(self.user_profile):
            LOGGER.info("user profile %s not found, skip clean env vars", self.user_profile)
            return

        install_path_escaped = re.escape(self.install_path)
        patterns = [
            re.compile(rf'^\s*export\s+PATH="{install_path_escaped}/bin":\$PATH\s*$'),
            re.compile(
                rf'^\s*export\s+LD_LIBRARY_PATH='
                rf'"{install_path_escaped}/lib":"{install_path_escaped}/add-ons"(?::\$LD_LIBRARY_PATH)?\s*$'
            ),
            re.compile(r'^\s*export\s+CMS_HOME=".*"\s*$'),
        ]
        try:
            with open(self.user_profile, "r", encoding="utf-8") as f:
                lines = f.readlines()
            filtered_lines = [
                line for line in lines
                if not any(pattern.match(line.strip()) for pattern in patterns)
            ]
            if filtered_lines != lines:
                with open(self.user_profile, "w", encoding="utf-8") as f:
                    f.writelines(filtered_lines)
        except OSError as e:
            _raise_unless_force(f"failed to clean env vars: {e}")

    def backup(self):
        """Backup config."""
        LOGGER.info("===== begin backup =====")
        config_json = os.path.join(self.cms_home, "cfg/cms.json")
        if os.path.exists(config_json):
            cmd = f"cp -arf {self.cms_home}/cfg/* {os.path.dirname(self.cms_old_config)}"
            run_cmd(cmd, "failed to backup config")
        else:
            _raise_unless_force(f"Config not found: {config_json}")
        LOGGER.info("===== backup done =====")

    def upgrade(self):
        """Upgrade config."""
        LOGGER.info("===== begin upgrade config =====")
        LOGGER.info("===== upgrade config done =====")

    def init_container(self):
        """Container init."""
        LOGGER.info("===== begin init container =====")
        if ProcessManager.is_running("cms server -start"):
            LOGGER.info("CMS already running")
            return

        if self.node_id == 0:
            from cms_startup import CmsStartup
            startup = CmsStartup()
            startup.init_container()

        self.install_step = 2
        self.set_cms_conf()
        LOGGER.info("===== init container done =====")



def main():
    cms = CmsCtl()

    if len(sys.argv) > 3 and sys.argv[1] == "uninstall" and sys.argv[2] == "override":
        global FORCE_UNINSTALL
        FORCE_UNINSTALL = sys.argv[3]

    if len(sys.argv) < 2:
        print("Usage: python3 cms_ctl.py <action>", file=sys.stderr)
        sys.exit(1)

    action = sys.argv[1]

    if action == "pre_install":
        if len(sys.argv) > 2:
            cms.install_type = sys.argv[2]
        cms.parse_parameters(cms.install_config_file)
        cms.pre_install()
        return

    if action == "install":
        cms.parse_parameters(cms.cms_new_config)
        cms.install()
        return

    if action in ("setup_files", "setup_gcc"):
        cms.parse_parameters(cms.cms_new_config)
        if action == "setup_files":
            cms.setup_files()
        else:
            cms.setup_gcc()
        return

    if action in ("start", "check_status", "stop", "uninstall", "backup", "upgrade", "init_container"):
        cms_json = cms.paths.cms_json
        if os.path.exists(cms_json):
            config_file = cms_json
        else:
            config_file = cms.install_config_file
        cms.parse_parameters(config_file)

        actions = {
            "start": cms.start,
            "check_status": cms.check_status,
            "stop": cms.stop,
            "uninstall": cms.uninstall,
            "backup": cms.backup,
            "upgrade": cms.upgrade,
            "init_container": cms.init_container,
        }
        actions[action]()


if __name__ == "__main__":
    try:
        main()
    except ValueError as err:
        sys.exit(str(err))
    sys.exit(0)
