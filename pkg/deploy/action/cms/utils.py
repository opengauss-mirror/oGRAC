"""
CMS 公共工具模块

重复代码归一：
  - exec_popen / run_cmd: 统一命令执行（替代 cmsctl.py 和 cms_node0_stop.py 中的重复实现）
  - check_backup_files / check_rollback_files: 统一备份校验（替代 appctl.sh 中的重复函数）
  - CGroup / IPTables / 进程管理: 统一系统操作
  - run_as_user: 用户切换执行
"""

import os
import sys
import re
import subprocess
import signal
import time
import glob as glob_mod
from log_config import get_logger

LOGGER = get_logger()



class CommandError(Exception):
    """命令执行失败的异常"""
    def __init__(self, cmd, returncode, stdout="", stderr=""):
        self.cmd = cmd
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        super().__init__(
            f"Command failed (rc={returncode}): {cmd}\n"
            f"stdout: {stdout}\nstderr: {stderr}"
        )


def exec_popen(cmd, timeout=1800):
    """
    统一的子进程执行函数。

    替代 cmsctl.py 和 cms_node0_stop.py 中各自独立的 _exec_popen()。

    Args:
        cmd: 要执行的 bash 命令字符串
        timeout: 超时秒数（默认 1800 秒）

    Returns:
        (returncode, stdout, stderr) 三元组
    """
    pobj = subprocess.Popen(
        ["bash"],
        shell=False,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        stdout_bytes, stderr_bytes = pobj.communicate(
            input=(cmd + os.linesep).encode(),
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        pobj.kill()
        pobj.communicate()
        return -1, "Time Out.", f"Command timed out after {timeout}s"

    stdout = stdout_bytes.decode().rstrip(os.linesep)
    stderr = stderr_bytes.decode().rstrip(os.linesep)
    return pobj.returncode, stdout, stderr


def run_cmd(cmd, error_msg="Command failed", force_uninstall=None):
    """
    执行命令并检查返回值，失败时抛出异常。

    统一替代 cmsctl.py 中的 run_cmd()。

    Args:
        cmd: bash 命令
        error_msg: 失败时的错误消息
        force_uninstall: 若为 "force" 则失败不抛出异常

    Returns:
        stdout 字符串

    Raises:
        CommandError: 命令失败且 force_uninstall != "force"
    """
    ret_code, stdout, stderr = exec_popen(cmd)
    if ret_code:
        output = stdout + stderr
        LOGGER.error("%s.\ncommand: %s.\noutput: %s" % (error_msg, cmd, output))
        if force_uninstall != "force":
            raise CommandError(cmd, ret_code, stdout, stderr)
    return stdout


def run_as_user(cmd, user, log_file=None):
    """
    以指定用户身份执行 shell 命令。

    适用于需要 shell 特性（source、管道、通配符）的场景。
    对于 Python-to-Python 调用，请使用 run_python_as_user()。

    Args:
        cmd: 要执行的 shell 命令字符串
        user: 目标用户
        log_file: 可选的日志重定向文件

    Returns:
        (returncode, stdout, stderr)
    """
    if log_file:
        full_cmd = f'su -s /bin/bash - {user} -c "{cmd} >> {log_file} 2>&1"'
    else:
        full_cmd = f'su -s /bin/bash - {user} -c "{cmd}"'
    return exec_popen(full_cmd)


def run_python_as_user(script, args, user, log_file=None, cwd=None, timeout=1800):
    """
    以指定用户身份执行 Python 脚本（结构化参数，无 shell 字符串拼接）。

    替代 run_as_user("python3 script arg1 arg2", user) 的反模式。
    使用 subprocess.Popen + preexec_fn 直接切换 uid/gid，参数以列表传递。

    优势：
      - 无 shell 注入风险
      - 参数包含空格/特殊字符时无需转义
      - 调用方传入结构化数据而非拼接字符串

    Args:
        script: Python 脚本路径
        args:   参数列表, 如 ["pre_install", "install"]
        user:   目标系统用户名
        log_file: 可选日志文件路径（stdout/stderr 追加写入）
        cwd:    工作目录（默认为脚本所在目录）
        timeout: 超时秒数（默认 1800）

    Returns:
        (returncode, stdout, stderr) 三元组
    """
    import pwd

    pw = pwd.getpwnam(user)
    uid, gid, home = pw.pw_uid, pw.pw_gid, pw.pw_dir

    def _demote():
        """preexec_fn: 在子进程 exec 前切换为目标用户"""
        os.setgid(gid)
        os.initgroups(user, gid)
        os.setuid(uid)

    env = os.environ.copy()
    env.update({"HOME": home, "USER": user, "LOGNAME": user})

    cmd_list = [sys.executable, script] + list(args)
    work_dir = cwd or os.path.dirname(os.path.abspath(script))
    log_fh = None

    try:
        if log_file:
            log_dir = os.path.dirname(log_file)
            if log_dir:
                os.makedirs(log_dir, exist_ok=True)
            log_fh = open(log_file, "a", encoding="utf-8")
            proc = subprocess.Popen(
                cmd_list, stdout=log_fh, stderr=subprocess.STDOUT,
                cwd=work_dir, env=env, preexec_fn=_demote,
            )
            proc.communicate(timeout=timeout)
            return proc.returncode, "", ""
        else:
            proc = subprocess.Popen(
                cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=work_dir, env=env, preexec_fn=_demote,
            )
            stdout_b, stderr_b = proc.communicate(timeout=timeout)
            return (
                proc.returncode,
                stdout_b.decode("utf-8", errors="replace").strip(),
                stderr_b.decode("utf-8", errors="replace").strip(),
            )
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        return -1, "", f"Timeout after {timeout}s"
    finally:
        if log_fh:
            log_fh.close()



def _parse_backup_list_line(line):
    """
    解析备份文件列表中的一行。

    Returns:
        (record_size, file_path) 或 (None, None) 如果行无效
    """
    line = line.strip()
    if not line:
        return None, None
    cleaned = line.replace(" ", "").lstrip("[")
    parts = cleaned.split("]", 1)
    if len(parts) < 2:
        return None, None
    record_size = parts[0]
    file_path = parts[1]
    if not file_path:
        return None, None
    if "->" in file_path:
        file_path = file_path.split("->")[0]
    return record_size, file_path


def check_backup_files(backup_list_file, dest_dir, orig_dir):
    """
    检查备份文件完整性。

    统一替代 appctl.sh 中 check_backup_files() 和 check_rollback_files() 的重复逻辑。

    Args:
        backup_list_file: 备份文件列表路径
        dest_dir: 备份目标目录
        orig_dir: 原始目录

    Raises:
        FileCheckError: 文件校验失败
    """
    LOGGER.info(f"check backup files in {dest_dir} from {orig_dir}")
    _do_file_check(backup_list_file, dest_dir, orig_dir, mode="backup")


def check_rollback_files(backup_list_file, dest_dir, orig_dir):
    """
    检查回滚文件完整性。

    Args:
        backup_list_file: 备份文件列表路径
        dest_dir: 备份目标目录
        orig_dir: 原始目录

    Raises:
        FileCheckError: 文件校验失败
    """
    LOGGER.info(f"check rollback files in {dest_dir} from {orig_dir}")
    _do_file_check(backup_list_file, dest_dir, orig_dir, mode="rollback")


class FileCheckError(Exception):
    """文件校验失败"""
    pass


def _do_file_check(backup_list_file, dest_dir, orig_dir, mode="backup"):
    """
    统一的文件校验实现。

    合并了原 check_backup_files 和 check_rollback_files 两个几乎一样的函数，
    通过 mode 参数区分 "backup"（检查dest是否存在）和 "rollback"（检查orig是否存在）。
    """
    with open(backup_list_file, "r") as f:
        for line in f:
            record_size, orig_path = _parse_backup_list_line(line)
            if not orig_path:
                continue
            if not orig_path.startswith(orig_dir):
                continue
            if orig_path.startswith(os.path.join(orig_dir, "log")):
                continue

            relative_path = orig_path[len(orig_dir):]
            dest_path = dest_dir + relative_path

            if mode == "backup":
                check_path = dest_path
            else:
                check_path = orig_path

            if not os.path.exists(check_path):
                msg = f"File not found: {orig_path} -> {dest_path}"
                LOGGER.error(msg)
                raise FileCheckError(msg)

            if os.path.isfile(check_path):
                orig_size = os.path.getsize(orig_path) if os.path.exists(orig_path) else 0
                dest_size = os.path.getsize(dest_path) if os.path.exists(dest_path) else 0
                if orig_size != dest_size:
                    msg = (f"File size mismatch: {orig_path}({orig_size}) "
                           f"-> {dest_path}({dest_size})")
                    LOGGER.error(msg)
                    raise FileCheckError(msg)
                if record_size and str(dest_size) != str(record_size):
                    msg = (f"File size differs from record: "
                           f"recorded={record_size}, actual={dest_size}")
                    LOGGER.error(msg)
                    raise FileCheckError(msg)



class CGroupManager:
    """CGroup 内存隔离管理"""

    def __init__(self, cgroup_path, mem_size_gb=10):
        self.cgroup_path = cgroup_path
        self.mem_size_gb = mem_size_gb

    def create(self):
        """创建 cgroup 路径"""
        os.makedirs(self.cgroup_path, exist_ok=True)
        LOGGER.info(f"cgroup path created: {self.cgroup_path}")

    def configure(self, process_keyword="cms server -start"):
        """设置内存限制并将进程加入"""
        limit_file = os.path.join(self.cgroup_path, "memory.limit_in_bytes")
        tasks_file = os.path.join(self.cgroup_path, "tasks")

        with open(limit_file, "w") as f:
            f.write(f"{self.mem_size_gb}G")
        LOGGER.info(f"cgroup memory limit set to {self.mem_size_gb}G")

        ret, stdout, _ = exec_popen(
            f"ps -ef | grep '{process_keyword}' | grep -v grep | awk 'NR==1 {{print $2}}'"
        )
        if ret == 0 and stdout.strip():
            pid = stdout.strip()
            with open(tasks_file, "w") as f:
                f.write(pid)
            LOGGER.info(f"added pid {pid} to cgroup")

    def clean(self):
        """清理 cgroup"""
        if os.path.isdir(self.cgroup_path):
            try:
                os.rmdir(self.cgroup_path)
                LOGGER.info(f"cgroup removed: {self.cgroup_path}")
            except OSError as e:
                LOGGER.warning(f"failed to remove cgroup: {e}")
        else:
            LOGGER.info("cgroup path does not exist, skip cleaning")

    def setup(self, process_keyword="cms server -start"):
        """完整的 cgroup 设置流程: clean -> create -> configure"""
        try:
            self.clean()
        except Exception:
            pass
        self.create()



class IPTablesManager:
    """IPTables 规则管理"""

    @staticmethod
    def _get_iptables_path():
        ret, stdout, _ = exec_popen("whereis iptables")
        if ret == 0 and stdout:
            path = stdout.split(":")[1].strip() if ":" in stdout else ""
            return path
        return ""

    @staticmethod
    def _rule_exists(chain, port):
        """检查规则是否已存在"""
        ret, stdout, _ = exec_popen(
            f"iptables -L {chain} -w 60 | grep ACCEPT | grep {port} | grep tcp | wc -l"
        )
        return ret == 0 and stdout.strip() != "0"

    @classmethod
    def accept(cls, cms_config_file):
        """
        添加 iptables ACCEPT 规则。
        统一替代 appctl.sh 中的 iptables_accept()。
        """
        port = cls._read_port(cms_config_file)
        if not port:
            LOGGER.warning("cannot read CMS port, skip iptables")
            return

        if not cls._get_iptables_path():
            LOGGER.info("iptables not found, skip")
            return

        LOGGER.info(f"adding iptables ACCEPT rules for port {port}")
        for chain in ("INPUT", "FORWARD", "OUTPUT"):
            if not cls._rule_exists(chain, port):
                exec_popen(f"iptables -I {chain} -p tcp --sport {port} -j ACCEPT -w 60")

    @classmethod
    def delete(cls, cms_config_file):
        """
        删除 iptables ACCEPT 规则。
        统一替代 appctl.sh 中的 iptables_delete()。
        """
        port = cls._read_port(cms_config_file)
        if not port:
            return

        if not cls._get_iptables_path():
            return

        LOGGER.info(f"deleting iptables rules for port {port}")
        for chain in ("INPUT", "FORWARD", "OUTPUT"):
            if cls._rule_exists(chain, port):
                exec_popen(f"iptables -D {chain} -p tcp --sport {port} -j ACCEPT -w 60")

    @staticmethod
    def _read_port(config_file):
        """从 cms.ini 中读取端口"""
        if not os.path.exists(config_file):
            return ""
        try:
            with open(config_file, "r") as f:
                for line in f:
                    if "_PORT" in line:
                        return line.split("=")[-1].strip()
        except OSError:
            pass
        return ""



class ProcessManager:
    """进程管理工具"""

    CHECK_MAX_TIMES = 7
    CHECK_INTERVAL = 5

    @staticmethod
    def get_pid(process_name):
        """获取进程 PID"""
        cmd = (
            f"ps -u $(id -un) -o pid=,args= | grep '{process_name}' | "
            "grep -v grep | awk '{print $1}'"
        )
        ret, stdout, stderr = exec_popen(cmd)
        if ret:
            LOGGER.error(f"Failed to get pid for '{process_name}': {stderr}")
            return ""
        return stdout.strip()

    @staticmethod
    def kill_process(process_name):
        """杀死指定进程"""
        kill_cmd = (
            f"proc_pid_list=$(ps -u $(id -un) -o pid=,args= | grep '{process_name}' | "
            "grep -v grep | awk '{print $1}') && "
            f'(if [ -n "$proc_pid_list" ]; then echo $proc_pid_list | xargs kill -9; fi)'
        )
        LOGGER.info(f"kill process: {process_name}")
        run_cmd(kill_cmd, f"failed to kill {process_name}")

    @classmethod
    def ensure_stopped(cls, process_name, force_uninstall=None):
        """确保进程已停止，最多等待 CHECK_MAX_TIMES * CHECK_INTERVAL 秒"""
        for i in range(cls.CHECK_MAX_TIMES):
            pid = cls.get_pid(process_name)
            if not pid:
                return
            LOGGER.info(f"check {i+1}/{cls.CHECK_MAX_TIMES}: {process_name} pid={pid}")
            if i < cls.CHECK_MAX_TIMES - 1:
                time.sleep(cls.CHECK_INTERVAL)

        msg = f"Failed to stop {process_name} after {cls.CHECK_MAX_TIMES * cls.CHECK_INTERVAL}s"
        LOGGER.error(msg)
        if force_uninstall != "force":
            raise RuntimeError(msg)

    @staticmethod
    def is_running(process_name):
        """检查进程是否在运行"""
        return bool(ProcessManager.get_pid(process_name))

    @staticmethod
    def clear_shm(shm_home="/dev/shm", shm_pattern="ograc.[0-9]*"):
        """
        清理共享内存（当 ogracd 未运行时）。

        Args:
            shm_home:    shm 目录（多实例时为隔离子目录，如 /dev/shm/ograc_alice）
            shm_pattern: 文件匹配模式（来自 InstanceConfig.shm_pattern）
        """
        shm_dir_name = os.path.basename(os.path.normpath(shm_home))
        cmd = ("ps -eo args= | grep '[o]gracd' "
               f"| grep '/dev/shm/{shm_dir_name}/'")
        ret, stdout, _ = exec_popen(cmd)
        if ret == 0 and stdout.strip():
            LOGGER.info("ogracd is running, skip shm cleanup")
            return
        if not os.path.isdir(shm_home):
            LOGGER.info(f"shm directory not found: {shm_home}, skip")
            return
        pattern = os.path.join(shm_home, shm_pattern)
        count = 0
        for f in glob_mod.glob(pattern):
            try:
                os.remove(f)
                count += 1
            except OSError:
                pass
        LOGGER.info(f"shared memory cleaned: {count} files from {shm_home}")

    @staticmethod
    def ensure_shm_dir(shm_home, user_and_group=""):
        """
        确保用户的 shm 子目录存在且权限正确（0700）。

        所有用户统一在 /dev/shm/{user}/ 下隔离，启动前自动创建。

        Args:
            shm_home:       用户的 shm 目录路径，如 /dev/shm/ograc
            user_and_group: 所有者，格式 "user:group"
        """
        if not os.path.isdir(shm_home):
            os.makedirs(shm_home, mode=0o700, exist_ok=True)
            LOGGER.info(f"created shm directory: {shm_home} (mode=0700)")
        if user_and_group:
            exec_popen(f"chown {user_and_group} {shm_home}")
            exec_popen(f"chmod 700 {shm_home}")



def ensure_dir(path, mode=0o750, owner=None):
    """确保目录存在并设置权限"""
    os.makedirs(path, mode=mode, exist_ok=True)
    if owner:
        run_cmd(f"chown {owner} -hR {path}", f"failed to chown {path}")


def ensure_file(path, mode=0o640, owner=None):
    """确保文件存在并设置权限"""
    if not os.path.exists(path):
        with open(path, "w"):
            pass
    os.chmod(path, mode)
    if owner:
        run_cmd(f"chown {owner} {path}", f"failed to chown {path}")


def safe_remove(path):
    """安全删除文件或目录"""
    if os.path.isfile(path) or os.path.islink(path):
        os.remove(path)
    elif os.path.isdir(path):
        import shutil
        shutil.rmtree(path)


def copy_tree(src, dest, owner=None):
    """复制目录树"""
    run_cmd(f"cp -arf {src} {dest}", f"failed to copy {src} to {dest}")
    if owner:
        run_cmd(f"chown -hR {owner} {dest}", f"failed to chown {dest}")



def read_version(versions_yml_path):
    """从 versions.yml 读取版本号"""
    if not os.path.exists(versions_yml_path):
        return ""
    with open(versions_yml_path, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("Version:"):
                return line.split(":")[1].strip()
    return ""


def get_version_major(versions_yml_path):
    """获取主版本号（第一位数字）"""
    version = read_version(versions_yml_path)
    if version:
        return int(version.split(".")[0])
    return 0
