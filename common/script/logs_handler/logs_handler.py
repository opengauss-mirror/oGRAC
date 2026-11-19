# Copyright (c) 2026 Huawei Technologies Co., Ltd.
# oGRAC is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

import os
import json
import subprocess
import signal
import importlib.util
from pathlib import Path
from logs_tool.log import LOGS_HANDLER_LOG as LOG

CUR_PATH, _ = os.path.split(os.path.abspath(__file__))
TIME_OUT = 300
FAIL = 1


def _resolve_action_config():
    candidates = []
    action_dir = os.environ.get("OGRAC_ACTION_DIR")
    if action_dir:
        candidates.append(Path(action_dir) / "config.py")

    root_dir = Path(CUR_PATH).resolve().parents[2]
    candidates.append(root_dir / "action" / "config.py")
    candidates.append(root_dir / "pkg" / "deploy" / "action" / "config.py")

    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError("new-flow action/config.py not found for logs handler")


def _load_runtime_cfg():
    action_config = _resolve_action_config()
    spec = importlib.util.spec_from_file_location("_ograc_action_config", action_config)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.get_config()


CFG = _load_runtime_cfg()
OGRAC_HOME = CFG.paths.ograc_home
DEPLOY_USER = CFG.deploy.ograc_user
DEPLOY_GROUP = CFG.deploy.ograc_group
OGMGR_USER = CFG.deploy.ogmgr_user


def file_reader(data_path):
    with open(data_path, 'r', encoding='utf-8') as file:
        info = file.read()
    return json.loads(info)


def get_param_value(param):
    if param == "deploy_user":
        return DEPLOY_USER
    if param == "deploy_group":
        return DEPLOY_GROUP
    return ""


def resolve_log_path(log_file_dir):
    if log_file_dir.startswith("${OGRAC_HOME}"):
        return log_file_dir.replace("${OGRAC_HOME}", OGRAC_HOME, 1)
    return log_file_dir


def resolve_user_and_group(user_and_group):
    if user_and_group == "deploy_user":
        return f"{DEPLOY_USER}:{DEPLOY_GROUP}"
    return user_and_group.replace("ogmgruser", OGMGR_USER)


def get_file_creation_time(file_path):
    ori_create_time = os.path.getctime(file_path)
    return int(round(ori_create_time * 1000))


def split_log_name(log_name):
    parts = log_name.rsplit(".", 1)
    if len(parts) != 2:
        return log_name, ""
    return parts[0], parts[1]


def is_rotated_log(log_name_prefix, log_name_tail, log_name, file_name):
    if not log_name_tail:
        return False
    if file_name.endswith("tar.gz") or file_name.endswith("swp") or file_name.endswith("swo"):
        return False
    if len(file_name) <= len(log_name):
        return False
    if not file_name.startswith(log_name_prefix) or not file_name.endswith(log_name_tail):
        return False

    middle = file_name[len(log_name_prefix):-len(log_name_tail)]
    return middle.startswith("_") and middle.endswith(".") and middle[1:-1].isdigit()


def close_child_process(proc):
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError as err:
        _ = err
        return 'success'
    except Exception as err:
        return str(err)

    return 'success'


def shell_task(exec_cmd):
    """
    subprocess.Popen in python3.
    param cmd: commands need to execute
    return: status code, standard output, error output
    """
    bash_cmd = ["bash"]
    pobj = subprocess.Popen(bash_cmd, shell=False, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
    pobj.stdin.write(exec_cmd.encode())
    pobj.stdin.write(os.linesep.encode())
    try:
        stdout, stderr = pobj.communicate(timeout=TIME_OUT)
    except Exception as err:
        return pobj.returncode, "", str(err)
    finally:
        return_code = pobj.returncode
        close_child_process(pobj)

    stdout, stderr = stdout.decode(), stderr.decode()
    if stdout[-1:] == os.linesep:
        stdout = stdout[:-1]
    if stderr[-1:] == os.linesep:
        stderr = stderr[:-1]

    return return_code, stdout, stderr


class LogsHandler:
    def __init__(self):
        self.config_params = file_reader(str(Path(CUR_PATH, 'config.json')))
        self.deploy_user = get_param_value("deploy_user")
        self.user_name = None

    def execute(self):
        for item in self.config_params:
            user = resolve_user_and_group(item.get('userandgroup', self.deploy_user))
            self.user_name = user.split(':')[0]
            log_file_dir = resolve_log_path(item.get('log_file_dir'))
            max_log_vol = int(item.get('max_log_vol'))
            if os.path.exists("/.dockerenv"):
                max_log_vol //= 2
            # 分离日志目录和日志名
            log_content, log_name = os.path.split(log_file_dir)
            if not os.path.exists(log_content):
                continue
            files_names = os.listdir(log_content)
            log_name_pre, log_name_tail = split_log_name(log_name)
            for file_name in files_names:
                if is_rotated_log(log_name_pre, log_name_tail, log_name, file_name):
                    # 判断当前是否有新产生的归档日志，有就退出循环进行打包操作
                    break
            else:
                continue
            exec_cmd = f"su - {self.user_name} -s /bin/bash -c 'python3 {CUR_PATH}/do_compress_and_archive.py " \
                       f"{log_content} {log_name} {max_log_vol} {self.user_name}' "
            return_code, stdout, stderr = shell_task(exec_cmd)

            if return_code or stderr:
                LOG.error(f'failed to execute log cleanup of {log_content}, '
                          f'return_code: {return_code}, stderr: {stderr}')
