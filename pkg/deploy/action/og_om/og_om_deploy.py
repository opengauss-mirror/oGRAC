#!/usr/bin/env python3
"""
og_om deploy orchestrator (runs as root).

Replaces appctl.sh (322 lines) + install/uninstall/pre_install/upgrade/
rollback/post_upgrade shell scripts with Python per REFACTOR_SPEC.

Responsibilities:
  - cgroup create/cleanup
  - ogctl command creation
  - permission management
  - install/uninstall/upgrade (tar extract/delete)
  - invoke og_om_ctl.py via run_python_as_user / run_shell_as_user
"""

import glob
import os
import pwd
import re
import shutil
import subprocess
import sys
import tarfile

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
if CUR_DIR not in sys.path:
    sys.path.insert(0, CUR_DIR)

from config import get_config, _parse_version
from log_config import get_logger
from utils import (
    CommandError, ensure_dir, ensure_file, exec_popen,
    run_python_as_user, run_shell_as_user,
    chown_recursive, chmod_recursive,
)

LOG = get_logger()


class OgOmDeploy:
    def __init__(self):
        self._cfg = get_config()
        self.paths = self._cfg.paths
        self.cgroup = self._cfg.cgroup
        self.timeout = self._cfg.timeout
        self.user = self._cfg.user
        self.group = self._cfg.group
        self.common_group = self._cfg.common_group
        self.ogmgr_user = self._cfg.ogmgr_user
        self.data_root = self._cfg.data_root
        self.version = self._cfg.version

    def _create_cgroup(self, cgroup_path):
        LOG.info(f"Creating cgroup: {cgroup_path}")
        if os.path.isdir(cgroup_path):
            try:
                os.rmdir(cgroup_path)
            except OSError:
                pass
        os.makedirs(cgroup_path, exist_ok=True)
        LOG.info(f"cgroup created: {cgroup_path}")

    def _rm_cgroup(self, cgroup_path):
        if os.path.isdir(cgroup_path):
            try:
                os.rmdir(cgroup_path)
                LOG.info(f"cgroup removed: {cgroup_path}")
            except OSError as e:
                LOG.warning(f"remove cgroup failed: {e}")
        else:
            LOG.info(f"cgroup not exist: {cgroup_path}")

    def _limit_cgroup_mem(self, cgroup_path, mem_limit):
        """Set cgroup memory.limit_in_bytes."""
        limit_file = os.path.join(cgroup_path, "memory.limit_in_bytes")
        rc, _, err = exec_popen(f'sh -c "echo {mem_limit} > {limit_file}"')
        if rc != 0:
            raise RuntimeError(f"cgroup memory limit failed: {err}")
        LOG.info(f"cgroup memory limit set: {cgroup_path} = {mem_limit}")

    def _add_pid_to_cgroup(self, pid, cgroup_path):
        tasks_file = os.path.join(cgroup_path, "tasks")
        rc, _, err = exec_popen(f'sh -c "echo {pid} > {tasks_file}"')
        if rc != 0:
            raise RuntimeError(f"add pid to cgroup failed: {err}")
        LOG.info(f"pid {pid} added to cgroup {cgroup_path}")

    def _create_ogctl(self):
        p = self.paths
        ogctl_content = (
            f'#!/bin/bash\n'
            f'su - {self.ogmgr_user} -s /bin/bash -c '
            f'"python3 {p.ogcli_main} $*"\n'
        )
        os.makedirs(os.path.dirname(p.ogctl_path), exist_ok=True)
        with open(p.ogctl_path, "w", encoding="utf-8") as f:
            f.write(ogctl_content)
        os.chmod(p.ogctl_path, 0o500)
        LOG.info(f"ogctl created at {p.ogctl_path}")

    def _correct_files_mod(self):
        """Set file permissions (replaces correct_ctom_files_mod + og_om_file_mod.sh).

        Uses 440 (owner+group readable) instead of 400 so ogmgr_user in the
        common group can also read .py scripts in the action directory.
        """
        exec_popen(f'chmod 440 "{CUR_DIR}"/*')
        exec_popen(f'chmod 755 "{CUR_DIR}"')

    def _correct_files_ownmod(self):
        """Set file ownership and modes (replaces correct_ctom_files_ownmod)."""
        p = self.paths
        ogmgr = f"{self.ogmgr_user}:{self.group}"
        user_cgroup = f"{self.user}:{self.common_group}"

        if os.path.isdir(p.service_dir):
            chown_recursive(p.service_dir, ogmgr)
            chmod_recursive(p.service_dir, "400")
            exec_popen(f'chown {user_cgroup} "{p.service_dir}"')
            chown_recursive(p.exporter_dir, user_cgroup)

        for d, mode in [
            (p.og_om_dir, "770"), (p.service_dir, "770"),
            (p.exporter_dir, "700"), (p.exporter_scripts, "700"),
            (p.exporter_exporter_dir, "700"), (p.exporter_config_dir, "700"),
            (p.exporter_query_dir, "755"),
            (p.ogcli_dir, "700"), (p.ogmgr_dir, "700"),
            (p.ogmgr_scripts, "700"), (p.ogmgr_checker_dir, "700"),
            (p.ogmgr_logs_collection, "700"), (p.ogmgr_log_tool, "700"),
            (p.ogmgr_tasks_dir, "700"), (p.ogmgr_common_dir, "700"),
            (p.ogmgr_tasks_inspection, "700"),
        ]:
            if os.path.isdir(d):
                exec_popen(f'chmod {mode} "{d}"')

        for f_path, mode in [
            (p.ogcli_commands_json, "600"),
            (p.ogmgr_format_note, "600"),
            (p.ogmgr_log_packing, "600"),
        ]:
            if os.path.isfile(f_path):
                exec_popen(f'chmod {mode} "{f_path}"')

    def _mod_prepare(self, action_type=""):
        p = self.paths
        ogmgr_owner = f"{self.ogmgr_user}:{self.common_group}"

        self._ensure_log_dir()

        ogmgr_files = ["og_om_ctl.py", "config.py", "log_config.py", "utils.py"]
        for fname in ogmgr_files:
            fpath = os.path.join(CUR_DIR, fname)
            if os.path.isfile(fpath):
                exec_popen(f'chown -h {ogmgr_owner} "{fpath}"')

        if action_type != "rollback" and not os.path.isfile(p.rpm_flag):
            dst = p.action_dir
            if os.path.realpath(CUR_DIR) != os.path.realpath(dst):
                action_parent = os.path.dirname(dst)
                if os.path.isdir(action_parent):
                    if os.path.isdir(dst):
                        shutil.rmtree(dst)
                    shutil.copytree(CUR_DIR, dst)
                    LOG.info(f"Copied action scripts to {dst}")

        LOG.info("mod_prepare done")

    def _install_og_om(self, install_type=""):
        p = self.paths

        if os.path.isfile(p.rpm_flag):
            rc, out, _ = exec_popen("rpm -qa | grep ograc_all_in_one")
            if rc == 0:
                LOG.info("RPM package already installed")
            return

        if os.path.isdir(p.og_om_dir) and os.listdir(p.og_om_dir):
            LOG.info("og_om exists, removing old installation")
            shutil.rmtree(p.og_om_dir)

        self._extract_package(p.og_om_dir)
        LOG.info("og_om install success")

    def _extract_package(self, target_dir, version=None, repo_dir=None):
        """Extract og_om package."""
        version = version or self.version
        repo = repo_dir or os.path.join(os.path.dirname(os.path.dirname(CUR_DIR)), "repo")

        if not version:
            versions_yml = os.path.join(os.path.dirname(os.path.dirname(CUR_DIR)), "versions.yml")
            raise RuntimeError(
                f"Cannot determine og_om version: versions.yml not found or missing 'Version' field "
                f"(expected at {versions_yml})"
            )

        pattern = os.path.join(repo, f"og_om-{version}*.tar.gz")
        pkgs = glob.glob(pattern)
        if not pkgs:
            raise FileNotFoundError(f"No package found: {pattern}")

        pkg = pkgs[0]
        os.makedirs(target_dir, exist_ok=True)

        with tarfile.open(pkg, "r:gz") as tar:
            tar.extractall(path=target_dir)

        nested_root = os.path.join(target_dir, os.path.basename(target_dir))
        nested_service = os.path.join(nested_root, "service")
        target_service = os.path.join(target_dir, "service")
        if os.path.isdir(nested_service) and not os.path.isdir(target_service):
            for item in os.listdir(nested_root):
                shutil.move(os.path.join(nested_root, item), os.path.join(target_dir, item))
            os.rmdir(nested_root)
            LOG.info("Flattened nested og_om package layout under %s", target_dir)

        self._patch_installed_service_files()
        LOG.info(f"Extracted {os.path.basename(pkg)} to {target_dir}")

    @staticmethod
    def _replace_file_content(path, replacements):
        if not os.path.isfile(path):
            return
        with open(path, encoding="utf-8") as f:
            old_content = f.read()
        new_content = old_content
        for old, new in replacements:
            new_content = new_content.replace(old, new)
        if new_content != old_content:
            with open(path, "w", encoding="utf-8") as f:
                f.write(new_content)

    @staticmethod
    def _regex_sub(content, pattern, replacement):
        return re.sub(pattern, replacement, content, flags=re.MULTILINE)

    @staticmethod
    def _replace_legacy_root(content, legacy_root, new_root):
        legacy_root = legacy_root.rstrip("/")
        new_root = new_root.rstrip("/")
        if not legacy_root or not new_root or legacy_root == new_root:
            return content

        pattern = re.escape(legacy_root)
        if new_root.startswith(legacy_root + os.sep):
            suffix = new_root[len(legacy_root):].strip(os.sep)
            first_segment = suffix.split(os.sep, 1)[0] if suffix else ""
            if first_segment:
                pattern += rf"(?!/{re.escape(first_segment)}(?:/|$))"

        return re.sub(pattern, new_root, content)

    @staticmethod
    def _replace_legacy_root_protected(content, legacy_root, new_root, also_protect=None):
        """Like _replace_legacy_root but also protects additional root paths from corruption."""
        legacy_root = legacy_root.rstrip("/")
        new_root = new_root.rstrip("/")
        if not legacy_root or not new_root or legacy_root == new_root:
            return content

        protect_segs = set()
        for root in [new_root] + (also_protect or []):
            if root and root.startswith(legacy_root + os.sep):
                seg = root[len(legacy_root):].strip(os.sep).split(os.sep, 1)[0]
                if seg:
                    protect_segs.add(seg)

        pattern = re.escape(legacy_root)
        if protect_segs:
            lookaheads = "|".join(re.escape(s) for s in sorted(protect_segs))
            pattern += rf"(?!/(?:{lookaheads})(?:/|$))"

        return re.sub(pattern, new_root, content)

    @staticmethod
    def _collapse_redundant_root(content, legacy_root, new_root):
        legacy_root = legacy_root.rstrip("/")
        new_root = new_root.rstrip("/")
        if not legacy_root or not new_root or not new_root.startswith(legacy_root + os.sep):
            return content

        suffix = new_root[len(legacy_root):].strip(os.sep)
        first_segment = suffix.split(os.sep, 1)[0] if suffix else ""
        if not first_segment:
            return content

        pattern = re.escape(legacy_root) + rf"(?:/{re.escape(first_segment)})+"
        return re.sub(pattern, new_root, content)

    def _normalize_legacy_service_content(self, path):
        if not os.path.isfile(path):
            return
        p = self.paths
        exporter_log_dir = os.path.join(p.ograc_home, "log", "ograc_exporter")
        ogmgr_log_dir = os.path.join(p.ogmgr_dir, "ogmgr_log")
        ogmgr_log_file = os.path.join(ogmgr_log_dir, "ogmgr_deploy.log")
        exporter_log_file = os.path.join(exporter_log_dir, "ograc_exporter.log")
        with open(path, encoding="utf-8") as f:
            old_content = f.read()
        new_content = old_content

        new_content = self._regex_sub(
            new_content,
            r'task_dir = \{\}  # 用于保存任务类，格式：\{命令: 命令对应的类\}\n',
            "task_dir = {}  # 用于保存任务类，格式：{命令: 命令对应的类}\n"
            "CUR_DIR = Path(__file__).resolve().parent\n\n"
            "def _normalize_file_path(file_path):\n"
            "    if not file_path:\n"
            "        return file_path\n"
            "    path_obj = Path(str(file_path))\n"
            "    if path_obj.is_absolute():\n"
            "        service_marker = Path(\"og_om\") / \"service\"\n"
            "        parts = path_obj.parts\n"
            "        for idx in range(len(parts) - 1):\n"
            "            if tuple(parts[idx:idx + 2]) == tuple(service_marker.parts):\n"
            "                return str(CUR_DIR.parent / Path(*parts[idx + 2:]))\n"
            "        return str(path_obj)\n"
            "    return str((CUR_DIR / path_obj).resolve())\n\n",
        )
        new_content = new_content.replace(
            "file_path = commend_data.get('filePath')",
            "file_path = _normalize_file_path(commend_data.get('filePath'))",
        )
        new_content = new_content.replace(
            "log_path, input_param = commend_data.get('filePath'), commend_data.get('py_input')",
            "log_path, input_param = _normalize_file_path(commend_data.get('filePath')), commend_data.get('py_input')",
        )
        new_content = self._regex_sub(
            new_content,
            r'"filePath":\s*"[^"\n]*/og_om/service/ogmgr/logs_collection/execute\.py"',
            '"filePath": "logs_collection/execute.py"',
        )
        new_content = self._regex_sub(
            new_content,
            r'["\'][^"\']*/og_om/service/ogmgr/uds_server\.py["\']',
            lambda m: f'{m.group(0)[0]}{p.ogmgr_uds_server}{m.group(0)[-1]}',
        )
        new_content = self._regex_sub(
            new_content,
            r'["\'][^"\']*/og_om/service/ograc_exporter/exporter/execute\.py["\']',
            lambda m: f'{m.group(0)[0]}{p.exporter_execute}{m.group(0)[-1]}',
        )
        new_content = self._regex_sub(
            new_content,
            r'["\'][^"\']*/og_om/service/og_om\.sock["\']',
            lambda m: f'{m.group(0)[0]}{os.path.join(p.service_dir, "og_om.sock")}{m.group(0)[-1]}',
        )
        new_content = new_content.replace("USER_UID = (6004,)", "USER_UID = (os.getuid(),)")
        new_content = self._regex_sub(
            new_content,
            r'python3\s+[^ \n]*/og_om/service/ogmgr/uds_server\.py\s*&',
            f'mkdir -p "{ogmgr_log_dir}"\n    nohup python3 "{p.ogmgr_uds_server}" >> "{ogmgr_log_file}" 2>&1 < /dev/null &',
        )
        new_content = self._regex_sub(
            new_content,
            r'python3\s+[^ \n]*/og_om/service/ograc_exporter/exporter/execute\.py\s*&',
            f'mkdir -p "{exporter_log_dir}"\n    nohup python3 "{p.exporter_execute}" >> "{exporter_log_file}" 2>&1 < /dev/null &',
        )
        new_content = new_content.replace(
            'SOCKET_SCRIPT="${OGMGR_DIR}/uds_server.py"',
            'SOCKET_SCRIPT="${OGMGR_DIR}/uds_server.py"\nDEPLOY_LOG="${OGMGR_DIR}/ogmgr_log/ogmgr_deploy.log"',
        )
        new_content = new_content.replace(
            'OGRAC_HOME=$(dirname "$(dirname "${SERVICE_DIR}")")',
            'OGRAC_HOME=$(dirname "$(dirname "${SERVICE_DIR}")")\n'
            'EXPORTER_LOG_DIR="${OGRAC_HOME}/log/ograc_exporter"\n'
            'EXPORTER_LOG_FILE="${EXPORTER_LOG_DIR}/ograc_exporter.log"',
        )
        new_content = new_content.replace(
            'python3 "${SOCKET_SCRIPT}" &',
            'mkdir -p "$(dirname "${DEPLOY_LOG}")"\n'
            '    nohup python3 "${SOCKET_SCRIPT}" >> "${DEPLOY_LOG}" 2>&1 < /dev/null &',
        )
        new_content = new_content.replace(
            'python3 "${UPPER_LEVEL_PATH}/${PYTHON_SCRIPT_PATH}"&',
            'mkdir -p "${EXPORTER_LOG_DIR}"\n'
            '    nohup python3 "${UPPER_LEVEL_PATH}/${PYTHON_SCRIPT_PATH}" >> "${EXPORTER_LOG_FILE}" 2>&1 < /dev/null &',
        )
        new_content = self._regex_sub(
            new_content,
            r'INSPECTION_JSON_FILE = "[^"\n]*/og_om/service/ogmgr/tasks/inspection/inspection_config\.json"',
            'INSPECTION_JSON_FILE = str(Path(DIR_NAME, "inspection_config.json"))',
        )
        new_content = self._regex_sub(
            new_content,
            r"sys\.path\.append\('[^'\n]*/og_om/service'\)",
            "SERVICE_ROOT = Path(__file__).resolve().parents[2]\nsys.path.append(str(SERVICE_ROOT))",
        )
        new_content = self._regex_sub(
            new_content,
            r"sys\.path\.append\('[^'\n]*/og_om/service/ogmgr'\)",
            "OGMGR_ROOT = Path(__file__).resolve().parents[1]\nsys.path.append(str(OGMGR_ROOT))",
        )
        new_content = self._regex_sub(
            new_content,
            r'(?<![A-Za-z0-9_])[/A-Za-z0-9._-]*/log/ograc_exporter',
            exporter_log_dir,
        )
        new_content = self._regex_sub(
            new_content,
            r'(?<![A-Za-z0-9_])[/A-Za-z0-9._-]*/log/og_om',
            p.log_dir,
        )
        new_content = self._collapse_redundant_root(new_content, "/opt/ograc", p.ograc_home)
        new_content = self._replace_legacy_root(
            new_content,
            "/opt/ograc/action/dbstor",
            os.path.join(self.paths.ograc_home, "action", "ograc_common"),
        )
        new_content = self._replace_legacy_root_protected(
            new_content, "/opt/ograc", p.ograc_home,
            also_protect=[self.data_root],
        )
        new_content = self._replace_legacy_root(new_content, "/mnt/dbdata", self.data_root)
        if new_content != old_content:
            with open(path, "w", encoding="utf-8") as f:
                f.write(new_content)

    def _patch_installed_service_files(self):
        p = self.paths
        replacements = [
            ("file_path = commend_data.get('filePath')", "file_path = _normalize_file_path(commend_data.get('filePath'))"),
            ("log_path, input_param = commend_data.get('filePath'), commend_data.get('py_input')",
             "log_path, input_param = _normalize_file_path(commend_data.get('filePath')), commend_data.get('py_input')"),
            ("USER_UID = (6004,)", "USER_UID = (os.getuid(),)"),
            ('SOCKET_SCRIPT="${OGMGR_DIR}/uds_server.py"',
             'SOCKET_SCRIPT="${OGMGR_DIR}/uds_server.py"\nDEPLOY_LOG="${OGMGR_DIR}/ogmgr_log/ogmgr_deploy.log"'),
            ('OGRAC_HOME=$(dirname "$(dirname "${SERVICE_DIR}")")',
             'OGRAC_HOME=$(dirname "$(dirname "${SERVICE_DIR}")")\n'
             'EXPORTER_LOG_DIR="${OGRAC_HOME}/log/ograc_exporter"\n'
             'EXPORTER_LOG_FILE="${EXPORTER_LOG_DIR}/ograc_exporter.log"'),
            ('python3 "${SOCKET_SCRIPT}" &',
             'mkdir -p "$(dirname "${DEPLOY_LOG}")"\n'
             '    nohup python3 "${SOCKET_SCRIPT}" >> "${DEPLOY_LOG}" 2>&1 < /dev/null &'),
            ('python3 "${UPPER_LEVEL_PATH}/${PYTHON_SCRIPT_PATH}"&',
             'mkdir -p "${EXPORTER_LOG_DIR}"\n'
             '    nohup python3 "${UPPER_LEVEL_PATH}/${PYTHON_SCRIPT_PATH}" >> "${EXPORTER_LOG_FILE}" 2>&1 < /dev/null &'),
        ]
        targets = [
            p.ogmgr_uds_server,
            os.path.join(p.ogmgr_dir, "task.py"),
            os.path.join(p.ogmgr_dir, "tasks.json"),
            os.path.join(p.ogmgr_dir, "tasks_example.json"),
            os.path.join(p.ogcli_dir, "uds_client.py"),
            p.start_ogmgr_sh,
            p.stop_ogmgr_sh,
            os.path.join(p.ogmgr_scripts, "log4sh.sh"),
            os.path.join(p.ogmgr_logs_collection, "execute.py"),
            os.path.join(p.exporter_scripts, "start_ograc_exporter.sh"),
            os.path.join(p.exporter_scripts, "stop_ograc_exporter.sh"),
            os.path.join(p.exporter_config_dir, "config.py"),
            os.path.join(p.exporter_exporter_dir, "get_info.py"),
            os.path.join(p.exporter_exporter_dir, "get_certificate_status.py"),
            os.path.join(p.ogmgr_logs_collection, "config.json"),
            os.path.join(p.ogmgr_tasks_inspection, "inspection_task.py"),
            os.path.join(p.ogmgr_tasks_inspection, "inspection_config.json"),
            os.path.join(p.ogmgr_logs_collection, "logs_collection.py"),
            os.path.join(p.exporter_query_dir, "get_dr_info.py"),
        ]
        for path in targets:
            self._replace_file_content(path, replacements)
            self._normalize_legacy_service_content(path)

    def _uninstall_og_om(self, force=False):
        p = self.paths

        if force:
            rc, pid, _ = exec_popen(
                f'ps -ef | grep "{p.ogmgr_uds_server}" | grep -v grep | awk \'{{print $2}}\''
            )
            if pid:
                exec_popen(f"kill -9 {pid}")
                LOG.info(f"Force killed ogmgr pid {pid}")

        rc, out, _ = exec_popen(
            f'ps -ef | grep "{p.ogmgr_uds_server}" | grep python | grep -v grep'
        )
        if out:
            raise RuntimeError("ogmgr still running, please stop first")

        rc, pid, _ = exec_popen(
            f'ps -ef | grep "{p.exporter_execute}" | grep -v grep | awk \'{{print $2}}\''
        )
        if pid:
            raise RuntimeError("ograc_exporter still running, please stop first")

        if os.path.isdir(p.og_om_dir) and os.listdir(p.og_om_dir):
            shutil.rmtree(p.og_om_dir)
            LOG.info("og_om uninstalled")
        else:
            LOG.info("og_om not installed, no need to uninstall")

    def _upgrade_og_om(self):
        p = self.paths
        if os.path.isdir(p.og_om_dir):
            shutil.rmtree(p.og_om_dir)
        self._extract_package(p.og_om_dir)
        LOG.info("og_om upgrade success")

    def _rollback_og_om(self, backup_dir):
        p = self.paths

        backup_versions = os.path.join(backup_dir, "versions.yml")
        rollback_version = _parse_version(backup_versions)
        if not rollback_version:
            raise RuntimeError("Cannot determine rollback version")

        if os.path.isdir(p.og_om_dir):
            shutil.rmtree(p.og_om_dir)

        backup_repo = os.path.join(backup_dir, "repo")
        self._extract_package(p.og_om_dir, version=rollback_version, repo_dir=backup_repo)
        LOG.info("og_om rollback success")

    def _post_upgrade_check(self):
        p = self.paths

        if not os.path.isdir(p.og_om_dir) or not os.listdir(p.og_om_dir):
            raise RuntimeError("og_om is not installed")

        pattern = os.path.join(p.repo_dir, "og_om-*.tar.gz")
        pkgs = glob.glob(pattern)
        if not pkgs:
            raise RuntimeError(f"No og_om tar.gz found in {p.repo_dir}")

        LOG.info("Post upgrade check ok")

    def _ensure_log_dir(self):
        """Ensure log directory exists with correct ownership; called before all ctl ops.

        og_om_ctl.py runs as ogmgr_user and must be able to traverse every
        parent directory up to log_dir. The log root is traversable by the
        instance management user; the og_om subdirectory is owned by it.
        """
        p = self.paths
        ogmgr_log = f"{self.ogmgr_user}:{self.group}"

        for parent in (p.ograc_home, os.path.join(p.ograc_home, "log")):
            if not os.path.isdir(parent):
                os.makedirs(parent, mode=0o750, exist_ok=True)
            exec_popen(f'chown {self.user}:{self.group} "{parent}"')
            exec_popen(f'chmod 750 "{parent}"')

        ensure_dir(p.log_dir, mode=0o750)
        exec_popen(f'chown {ogmgr_log} "{p.log_dir}"')
        exec_popen(f'chmod 750 "{p.log_dir}"')

        if not os.path.isfile(p.log_file):
            open(p.log_file, "a").close()
        exec_popen(f'chown {ogmgr_log} "{p.log_file}"')
        exec_popen(f'chmod 640 "{p.log_file}"')

    def _run_ctl_as_ogmgr(self, action):
        self._patch_installed_service_files()
        self._ensure_log_dir()
        try:
            pwd.getpwnam(self.ogmgr_user)
        except KeyError:
            raise RuntimeError(f"ogmgr user not found: {self.ogmgr_user}")
        if action == "start" and not os.path.isfile(self.paths.start_ogmgr_sh):
            raise RuntimeError(
                f"og_om start script not found: {self.paths.start_ogmgr_sh}. "
                "og_om may not be installed completely"
            )
        script = os.path.join(CUR_DIR, "og_om_ctl.py")
        op_timeout = self.timeout.get(action)
        rc, out, err = run_python_as_user(
            script, [action], self.ogmgr_user,
            log_file=self.paths.log_file,
            timeout=op_timeout,
        )
        if rc != 0:
            raise CommandError(f"og_om_ctl.py {action}", rc, out, err)
        for part in (out, err):
            if not part:
                continue
            for line in part.splitlines():
                if line.strip():
                    LOG.info(line)

    def action_start(self):
        self._run_ctl_as_ogmgr("start")

    def action_stop(self):
        self._run_ctl_as_ogmgr("stop")

    def action_check_status(self):
        self._run_ctl_as_ogmgr("check_status")

    def action_install(self):
        """Install action (replaces appctl.sh install branch)."""
        self._create_ogctl()
        self._correct_files_mod()
        self._mod_prepare()
        self._install_og_om()
        self._correct_files_ownmod()
        p = self.paths
        if os.path.isfile(p.exporter_logicrep_sql):
            exec_popen(f'chmod 600 "{p.exporter_logicrep_sql}"')

    def action_uninstall(self):
        """Uninstall action (replaces appctl.sh uninstall branch)."""
        force = len(sys.argv) > 2 and sys.argv[2] == "force"
        self._uninstall_og_om(force=force)
        self._rm_cgroup(self.cgroup.exporter_cgroup)
        self._rm_cgroup(self.cgroup.ogmgr_cgroup)

    def action_upgrade(self):
        """Upgrade action (replaces appctl.sh upgrade branch)."""
        self._correct_files_mod()
        self._mod_prepare()
        self._upgrade_og_om()
        self._correct_files_ownmod()

    def action_rollback(self):
        """Rollback action (replaces appctl.sh rollback branch)."""
        if len(sys.argv) < 3:
            raise RuntimeError("rollback requires backup directory path argument")
        backup_dir = sys.argv[2]
        self._correct_files_mod()
        self._mod_prepare(action_type="rollback")
        self._rollback_og_om(backup_dir)
        self._correct_files_ownmod()

    def action_post_upgrade(self):
        self._post_upgrade_check()

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



def main():
    if len(sys.argv) < 2:
        print("Usage: python3 og_om_deploy.py <action>", file=sys.stderr)
        sys.exit(1)

    action = sys.argv[1]
    deployer = OgOmDeploy()

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
