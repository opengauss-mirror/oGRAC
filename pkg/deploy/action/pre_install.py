#!/usr/bin/env python3
"""oGRAC pre-install checks and config generation."""

import abc
import os
import re
import subprocess
import shlex
import socket
import sys
import stat
import json
import collections
from pathlib import Path

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
if CUR_DIR not in sys.path:
    sys.path.insert(0, CUR_DIR)

from log_config import get_logger
from config import get_config, get_module_config

LOG = get_logger("deploy")
cfg = get_config()

INSTALL_PATH = cfg.paths.ograc_home
OGRACD_INI_FILE = cfg.paths.ogracd_ini
RPMINSTALLED_TAG = cfg.paths.rpm_flag
OGRAC_MEM_SPEC_FILE = os.path.join(
    CUR_DIR, "config", "container_conf", "init_conf", "mem_spec")

NEEDED_SIZE = 20580
NEEDED_MEM_SIZE = 16 * 1024

ip_check_element = {'ograc_vlan_ip', 'cms_ip'}
ping_check_element = {
    'ograc_vlan_ip', 'cms_ip',
    'share_logic_ip', 'archive_logic_ip', 'metadata_logic_ip',
}

kernel_element = {
    'TEMP_BUFFER_SIZE', 'DATA_BUFFER_SIZE', 'SHARED_POOL_SIZE',
    'LOG_BUFFER_SIZE', 'SESSIONS', 'VARIANT_MEMORY_AREA_SIZE',
    '_INDEX_BUFFER_SIZE',
}

UnitConversionInfo = collections.namedtuple(
    'UnitConversionInfo',
    ['tmp_gb', 'tmp_mb', 'tmp_kb', 'key', 'value',
     'sga_buff_size', 'temp_buffer_size', 'data_buffer_size',
     'shared_pool_size', 'log_buffer_size'])


class ConfigChecker:
    @staticmethod
    def node_id(value):
        return value in {'0', '1'}

    @staticmethod
    def install_type(value):
        return value in {'override', 'reserve'}

    @staticmethod
    def link_type(value):
        return value in {'1', '0', '2'}

    @staticmethod
    def db_type(value):
        return value in {'0', '1', '2'}

    @staticmethod
    def deploy_mode(value):
        return value in {"file", "dss"}

    @staticmethod
    def ograc_in_container(value):
        return value in {'0', '1', '2'}

    @staticmethod
    def cluster_id(value):
        try:
            v = int(value)
        except (ValueError, TypeError):
            return False
        return 0 <= v <= 255

    @staticmethod
    def cluster_name(value):
        return bool(value) and len(value) <= 64

    @staticmethod
    def mes_type(value):
        return value in {"UC", "TCP", "UC_RDMA"}

    @staticmethod
    def mes_ssl_switch(value):
        return isinstance(value, bool)

    @staticmethod
    def redo_num(value):
        try:
            v = int(value)
        except (ValueError, TypeError):
            return False
        return 3 <= v <= 256

    @staticmethod
    def redo_size(value):
        if not value.endswith("G"):
            return False
        try:
            return int(value.strip("G")) > 0
        except (ValueError, TypeError):
            return False

    @staticmethod
    def ca_path(value):
        return os.path.exists(value)

    @staticmethod
    def crt_path(value):
        return os.path.exists(value)

    @staticmethod
    def key_path(value):
        return os.path.exists(value)

    @staticmethod
    def auto_tune(value):
        return value in {'0', '1'}


class CheckBase(metaclass=abc.ABCMeta):
    def __init__(self, check_name, suggestion):
        self.check_name = check_name
        self.suggestion = suggestion

    def check(self, *args, **kwargs):
        LOG.info("[Check Item]-[%s]: begin", self.check_name)
        check_result = False
        try:
            check_result = self.get_result(*args, **kwargs)
        except Exception as error:
            LOG.error("[Check Item]-[%s]: error: %s", self.check_name, str(error))
        LOG.info("[Check Item]-[%s]: result: %s", self.check_name, str(check_result))
        return check_result, [self.check_name, self.suggestion]

    @abc.abstractmethod
    def get_result(self, *args, **kwargs):
        return True


class CheckMem(CheckBase):
    def __init__(self):
        super().__init__(
            f'memory available size smaller than {NEEDED_MEM_SIZE}M',
            f'current memory size {self.get_mem_available()}M')

    @staticmethod
    def get_mem_available():
        res = 0
        with open('/proc/meminfo') as fp:
            for line in fp:
                if "MemFree:" in line:
                    res += int(line.split(':')[1].strip().split()[0]) // 1024
                if "MemAvailable" in line:
                    res += int(line.split(':')[1].strip().split()[0]) // 1024
        return res

    def get_result(self, *args, **kwargs):
        return self.get_mem_available() >= NEEDED_MEM_SIZE


class CheckDisk(CheckBase):
    def __init__(self):
        super().__init__(
            f'disk capacity available size smaller than {NEEDED_SIZE}M',
            f'current disk capacity {self.get_disk_available()}M')

    @staticmethod
    def find_dir_path():
        _path = INSTALL_PATH
        while not os.path.isdir(_path):
            _path = os.path.dirname(_path)
        return _path

    def get_disk_available(self):
        fs_info = os.statvfs(self.find_dir_path())
        return fs_info.f_bavail * fs_info.f_frsize / (1024 * 1024)

    def get_result(self, *args, **kwargs):
        return self.get_disk_available() >= NEEDED_SIZE


class CheckInstallPath(CheckBase):
    def __init__(self):
        super().__init__("check install path is right.", "please check install path")

    def get_result(self, *args, **kwargs):
        return not (os.path.exists(INSTALL_PATH) and not os.path.isdir(INSTALL_PATH))


class CheckInstallConfig(CheckBase):
    def __init__(self, config_path=None):
        super().__init__(
            "check config param",
            f'please check params in json file {config_path}')
        self.config_path = config_path
        self.value_checker = ConfigChecker

        self.config_key = {
            'node_id', 'cms_ip',
            'storage_share_fs', 'storage_archive_fs', 'storage_metadata_fs',
            'share_logic_ip', 'archive_logic_ip', 'metadata_logic_ip',
            'db_type', 'MAX_ARCH_FILES_SIZE', 'deploy_mode',
            'mes_ssl_switch', 'ograc_in_container', 'deploy_policy',
            'link_type', 'ca_path', 'crt_path', 'key_path',
        }

        self.dss_config_key = {
            'node_id', 'cms_ip', 'db_type',
            'ograc_in_container', 'MAX_ARCH_FILES_SIZE',
            'deploy_mode', 'mes_ssl_switch', 'redo_num', 'redo_size',
            'auto_tune', 'dss_vg_list', 'gcc_home',
            'cms_port', 'dss_port', 'ograc_port', 'interconnect_port',
        }
        if os.path.exists(RPMINSTALLED_TAG):
            self.dss_config_key.add('SYS_PASSWORD')

        self.file_config_key = {"redo_num", "redo_size"}
        self.mes_type_key = {"ca_path", "crt_path", "key_path"}
        self.config_params = {}
        self.cluster_name = None

    @staticmethod
    def check_ipv4(_ip):
        try:
            socket.inet_pton(socket.AF_INET, _ip)
            return True
        except (AttributeError, socket.error):
            return False

    @staticmethod
    def check_ipv6(_ip):
        try:
            socket.inet_pton(socket.AF_INET6, _ip)
            return True
        except socket.error:
            return False

    @staticmethod
    def execute_cmd(cmd):
        cmd_list = cmd.split("|")
        process_list = []
        for index, c in enumerate(cmd_list):
            stdin = process_list[index - 1].stdout if index > 0 else None
            _p = subprocess.Popen(
                shlex.split(c), stdin=stdin,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
            process_list.append(_p)
        try:
            stdout, stderr = process_list[-1].communicate(timeout=30)
        except Exception as err:
            return -1, str(err), -1
        return (stdout.decode().strip("\n"),
                stderr.decode().strip("\n"),
                process_list[-1].returncode)

    @staticmethod
    def check_ograc_mem_spec():
        if os.path.exists(OGRAC_MEM_SPEC_FILE):
            with open(OGRAC_MEM_SPEC_FILE, encoding="utf-8") as f:
                mem_spec = json.load(f)
            if mem_spec not in ["0", "1", "2", "3"]:
                LOG.error("Check mem spec failed, current value[%s]", mem_spec)
                return False
        return True

    def read_install_config(self):
        try:
            with open(self.config_path, 'r', encoding='utf8') as fp:
                return json.load(fp)
        except Exception as error:
            LOG.error('load %s error: %s', self.config_path, str(error))
        return {}

    def check_install_config_params(self, install_config):
        for element in self.config_key:
            if element not in install_config:
                LOG.error('config_params.json need param %s', element)
                return False
        return True

    def check_install_config_param(self, key, value):
        if hasattr(self.value_checker, key):
            if not getattr(self.value_checker, key)(value):
                return False

        if key in ip_check_element:
            for single_ip in re.split(r"[;,|]", value):
                if not self.check_ipv4(single_ip) and not self.check_ipv6(single_ip):
                    return False

        if key in ping_check_element:
            for node_ip in re.split(r"[;,|]", value):
                cmd = "%s %s -i 1 -c 3 | grep ttl | wc -l"
                try:
                    ret, _, _ = self.execute_cmd(cmd % ("ping", node_ip))
                except Exception:
                    ret = -1
                try:
                    ret6, _, _ = self.execute_cmd(cmd % ("ping6", node_ip))
                except Exception:
                    ret6 = -1
                if ret != "3" and ret6 != "3":
                    return False
        return True

    def write_result_to_json(self):
        modes = stat.S_IRWXU | stat.S_IROTH | stat.S_IRGRP
        flag = os.O_RDWR | os.O_CREAT | os.O_TRUNC
        deploy_param = os.path.join(CUR_DIR, "deploy_param.json")
        with os.fdopen(os.open(deploy_param, flag, modes), 'w') as fp:
            fp.write(json.dumps(self.config_params, indent=4))

    def generate_install_config(self):
        """Derive and write install_config.json from ograc_config.json and module_config."""
        ograc_cfg_file = os.path.join(CUR_DIR, "ograc", "ograc_config.json")
        ograc_raw = {}
        if os.path.exists(ograc_cfg_file):
            try:
                with open(ograc_cfg_file, encoding="utf-8") as f:
                    ograc_raw = json.load(f)
            except (json.JSONDecodeError, OSError):
                pass

        mc = get_module_config()
        ograc_home = mc.get("ograc_home", ograc_raw.get("ograc_home", "/opt/ograc"))
        data_root = mc.get("data_root", ograc_raw.get("data_root", "/mnt/dbdata"))

        deploy_mode = self.config_params.get("deploy_mode", "file")
        running_mode = "ogracd" if deploy_mode == "standalone" else "ogracd_in_cluster"

        install_conf = {
            "R_INSTALL_PATH": os.path.join(ograc_home, "ograc", "server"),
            "D_DATA_PATH": os.path.join(data_root, "local", "ograc", "tmp", "data"),
            "l_LOG_FILE": os.path.join(ograc_home, "log", "ograc", "ograc_deploy.log"),
            "M_RUNING_MODE": running_mode,
            "OG_CLUSTER_STRICT_CHECK": "TRUE",
            "Z_KERNEL_PARAMETER1": "CHECKPOINT_PERIOD=1",
            "Z_KERNEL_PARAMETER2": "OPTIMIZED_WORKER_THREADS=2000",
        }

        install_config_path = os.path.join(CUR_DIR, "ograc", "install_config.json")
        if os.path.exists(install_config_path):
            try:
                with open(install_config_path, encoding="utf-8") as f:
                    existing = json.load(f)
                for k, v in existing.items():
                    if k not in install_conf:
                        install_conf[k] = v
            except (json.JSONDecodeError, OSError):
                pass

        ograc_dir = os.path.join(CUR_DIR, "ograc")
        os.makedirs(ograc_dir, exist_ok=True)

        modes = stat.S_IRWXU | stat.S_IROTH | stat.S_IRGRP
        flag = os.O_RDWR | os.O_CREAT | os.O_TRUNC
        with os.fdopen(os.open(install_config_path, flag, modes), 'w') as fp:
            fp.write(json.dumps(install_conf, indent=4))
        LOG.info("Generated install_config.json at %s", install_config_path)

    def update_config_params(self):
        if (self.config_params.get("share_logic_ip") == "" and
                self.config_params.get("archive_logic_ip") == "" and
                self.config_params.get("metadata_logic_ip") == ""):
            self.config_params["share_logic_ip"] = self.config_params.get("cluster_name", "")
            self.config_params["archive_logic_ip"] = self.config_params.get("cluster_name", "")
            self.config_params["metadata_logic_ip"] = self.config_params.get("cluster_name", "")
            modes = stat.S_IRWXU | stat.S_IROTH | stat.S_IRGRP
            flag = os.O_RDWR | os.O_CREAT | os.O_TRUNC
            with os.fdopen(os.open(self.config_path, flag, modes), 'w') as fp:
                fp.write(json.dumps(self.config_params, indent=4))

    def do_unit_conversion(self, info):
        tmp_gb, tmp_mb, tmp_kb, key, value, \
            sga_buff_size, temp_buffer_size, data_buffer_size, \
            shared_pool_size, log_buffer_size = info
        if value[:-1].isdigit() and value[-1:] in ("G", "M", "K"):
            unit_map = {"G": tmp_gb, "M": tmp_mb, "K": tmp_kb}
            sga_buff_size += int(value[:-1]) * unit_map[value[-1:]]

        key_subtract_map = {
            "TEMP_BUFFER_SIZE": temp_buffer_size,
            "DATA_BUFFER_SIZE": data_buffer_size,
            "SHARED_POOL_SIZE": shared_pool_size,
            "LOG_BUFFER_SIZE": log_buffer_size,
        }
        if key in key_subtract_map:
            sga_buff_size -= key_subtract_map[key]
        if key == "SESSIONS":
            sga_buff_size += int(value) * 5.5 * tmp_gb / 1024
        return sga_buff_size

    def check_sga_buff_size(self):
        LOG.info("Checking sga buff size.")
        tmp_gb = 1024 * 1024 * 1024
        tmp_mb = 1024 * 1024
        tmp_kb = 1024
        log_buffer_size = 4 * tmp_mb
        shared_pool_size = 128 * tmp_mb
        data_buffer_size = 128 * tmp_mb
        temp_buffer_size = 32 * tmp_mb
        sga_buff_size = (log_buffer_size + shared_pool_size +
                         data_buffer_size + temp_buffer_size)

        if not os.path.exists(OGRACD_INI_FILE):
            LOG.warning("ogracd.ini not found, skip sga check")
            return True

        modes = stat.S_IWUSR | stat.S_IRUSR
        with os.fdopen(os.open(OGRACD_INI_FILE, os.O_RDONLY, modes), 'r') as fp:
            for line in fp:
                if line.strip() == "" or " = " not in line:
                    continue
                key, value = line.split(" = ", 1)
                if key in kernel_element:
                    info = UnitConversionInfo(
                        tmp_gb, tmp_mb, tmp_kb, key, value.strip(),
                        sga_buff_size, temp_buffer_size, data_buffer_size,
                        shared_pool_size, log_buffer_size)
                    sga_buff_size = self.do_unit_conversion(info)

        if sga_buff_size < 114 * tmp_mb:
            LOG.error("sga buffer size should not less than 114MB")
            return False

        sga_buff_size += 2.2 * tmp_gb
        cmd = ("cat /proc/meminfo | grep -wE 'MemFree:|Buffers:|Cached:|SwapCached' "
               "| awk '{sum += $2};END {print sum}'")
        proc = subprocess.Popen(
            ["bash", "-c", cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = proc.communicate(timeout=30)
        if proc.returncode:
            LOG.error("cannot get shmmax parameters")
            return False
        cur_avi_memory = stdout.decode().strip()
        if int(sga_buff_size) > int(cur_avi_memory) * tmp_kb:
            LOG.error("sga buffer size exceeds available memory")
            return False

        return True

    def install_config_params_init(self, params):
        defaults = {
            'link_type': '1', 'storage_archive_fs': '', 'archive_logic_ip': '',
            'mes_type': 'UC', 'mes_ssl_switch': False, 'deploy_mode': 'file',
            'db_type': '0', 'ograc_in_container': '0', 'auto_tune': False,
            'cms_port': '14587', 'ograc_port': '1611',
            'interconnect_port': '1601,1602',
        }
        for k, v in defaults.items():
            if k not in params:
                params[k] = v
        if (params.get("mes_ssl_switch") and
                params.get("ograc_in_container", "-1") == "0"):
            self.config_key.update(self.mes_type_key)

    @staticmethod
    def init_config_by_deploy_policy(params):
        deploy_policy_key = params.get("deploy_policy", "")
        if deploy_policy_key in ("", "default"):
            params["deploy_policy"] = "default"
            return True
        LOG.error("Unsupported deploy policy '%s' (only 'default' is supported)",
                  deploy_policy_key)
        return False

    def get_result(self, *args, **kwargs):
        if not self.config_path:
            LOG.error('path of config file is not entered')
            return False

        install_config_params = self.read_install_config()
        if not install_config_params:
            return False

        if not self.init_config_by_deploy_policy(install_config_params):
            LOG.error("init deploy policy failed")
            return False

        if install_config_params.get("deploy_mode") == "dss":
            self.config_key = self.dss_config_key

        self.install_config_params_init(install_config_params)
        self.cluster_name = install_config_params.get("cluster_name")

        deploy_mode = install_config_params.get("deploy_mode", "file")
        if deploy_mode == "file":
            self.config_params['cluster_id'] = "0"
            self.config_params['mes_type'] = "TCP"
            self.config_key.update(self.file_config_key)

        if install_config_params.get("storage_archive_fs") == "":
            ping_check_element.discard("archive_logic_ip")

        if install_config_params.get("ograc_in_container", "0") != '0':
            ip_check_element.discard('cms_ip')
            ping_check_element.discard("cms_ip")
            ip_check_element.discard("ograc_vlan_ip")
            ping_check_element.discard("ograc_vlan_ip")

        if deploy_mode == "dss":
            for k in ('ograc_vlan_ip', 'cms_ip'):
                ip_check_element.discard(k)
                ping_check_element.discard(k)
            for k in ('share_logic_ip', 'metadata_logic_ip'):
                ping_check_element.discard(k)

        max_arch = install_config_params.get('MAX_ARCH_FILES_SIZE', "")
        if not max_arch:
            install_config_params['MAX_ARCH_FILES_SIZE'] = '300G'

        if not self.check_install_config_params(install_config_params):
            return False

        for key, value in install_config_params.items():
            if not install_config_params.get("mes_ssl_switch") and key in self.mes_type_key:
                continue
            if key in self.config_key:
                if not self.check_install_config_param(key, value):
                    LOG.error('check %s with value: %s failed', key, str(value))
                    return False
                self.config_params[key] = value

        try:
            self.update_config_params()
        except Exception as error:
            LOG.error('write config params failed: %s', str(error))
            return False

        if install_config_params.get("ograc_in_container", "0") == '0':
            try:
                self.write_result_to_json()
            except Exception as error:
                LOG.error('write deploy_param.json failed: %s', str(error))
                return False

        try:
            self.generate_install_config()
        except Exception as error:
            LOG.error('generate install_config.json failed: %s', str(error))
            return False

        return True

    def sga_buffer_check(self):
        if not self.check_ograc_mem_spec():
            return False
        return self.check_sga_buff_size()


class PreInstall:
    def __init__(self, install_model, config_path):
        self.config_path = config_path
        self.install_model = install_model

    @staticmethod
    def run_sga_buffer_check():
        check_config = CheckInstallConfig()
        if not check_config.sga_buffer_check():
            LOG.error('sga buffer check failed')
            return 1
        return 0

    def check_main(self):
        if self.install_model == "override":
            check_items = [CheckMem, CheckDisk, CheckInstallPath, CheckInstallConfig]
        else:
            check_items = [CheckMem, CheckDisk, CheckInstallPath]

        for item in check_items:
            if item is CheckInstallConfig:
                res = item(self.config_path).get_result()
            else:
                res = item().get_result()
            if not res:
                LOG.error('failed: %s', item.__name__)
                return 1
        return 0


if __name__ == '__main__':
    config_file = None
    install_type = sys.argv[1]
    if install_type == 'sga_buffer_check':
        sys.exit(PreInstall.run_sga_buffer_check())
    elif install_type == 'override':
        config_file = sys.argv[2]
        pre_install = PreInstall(install_type, config_file)
        sys.exit(pre_install.check_main())
