#!/usr/bin/env python3
"""oGRAC configuration updater."""
import os
import sys
import stat
import json
import subprocess
import configparser
import argparse
import traceback

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
ACTION_DIR = os.path.dirname(CUR_DIR)
sys.path.insert(0, ACTION_DIR)

from config import get_config
from log_config import get_logger
from utils import exec_popen

LOG = get_logger("deploy")
cfg = get_config()


def get_env_info(key):
    deploy = cfg.deploy
    env_map = {
        "ograc_user": deploy.ograc_user,
        "ograc_group": deploy.ograc_group,
        "ograc_common_group": deploy.ograc_common_group,
    }
    return env_map.get(key, "")


def modify_ini_file(file_path, section, option, action, value=None):
    config = configparser.ConfigParser()
    config.optionxform = str
    config.read(file_path)
    if action == "add":
        if section in config:
            config[section][option] = value
        else:
            config[section] = {option: value}
    else:
        if section in config and option in config[section]:
            config.remove_option(section, option)
    flags = os.O_CREAT | os.O_RDWR
    modes = stat.S_IWUSR | stat.S_IRUSR
    with os.fdopen(os.open(file_path, flags, modes), "w") as fp:
        fp.truncate(0)
        config.write(fp)


def read_deploy_conf(file_path=None):
    if file_path is None:
        file_path = os.path.join(cfg.paths.config_dir, "deploy_param.json")
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_config_file(file_path, content):
    flags = os.O_RDWR | os.O_CREAT | os.O_TRUNC
    modes = stat.S_IRWXU | stat.S_IROTH | stat.S_IRGRP
    with os.fdopen(os.open(file_path, flags, modes), "w") as fp:
        fp.write(json.dumps(content, indent=4))


def update_ograc_conf(action, key, value):
    file_path = os.path.join(cfg.paths.ograc_app_home, "cfg", "ograc_config.json")
    if not os.path.exists(file_path):
        LOG.warning("ograc_config.json not found: %s", file_path)
        return
    config = read_deploy_conf(file_path=file_path)
    config["LOG_HOME"] = cfg.logs.log_dir("ograc")
    write_config_file(file_path, config)


def update_cms_conf(action, key, value):
    deploy_config = read_deploy_conf()
    file_path = os.path.join(cfg.paths.cms_home, "cfg", "cms.json")
    if key == "cms_reserve":
        file_path = os.path.join(cfg.paths.backup_dir, "files", "cms.json")
    if not os.path.exists(file_path):
        LOG.warning("cms.json not found: %s", file_path)
        return
    config = read_deploy_conf(file_path=file_path)
    config["user"] = get_env_info("ograc_user")
    config["group"] = get_env_info("ograc_group")
    config["user_profile"] = f"/home/{get_env_info('ograc_user')}/.bashrc"
    config["user_home"] = f"/home/{get_env_info('ograc_user')}"
    config["share_logic_ip"] = deploy_config.get("share_logic_ip", "")
    write_config_file(file_path, config)


def update_ini_conf(file_path, action, key, value):
    if not os.path.exists(file_path):
        LOG.warning("INI file not found: %s", file_path)
        return
    with open(file_path, "r", encoding="utf-8") as fp:
        config = fp.readlines()
    found = False
    for i, item in enumerate(config):
        if key in item:
            found = True
            if action == "update":
                config[i] = f"{key} = {value}\n"
            elif action == "del":
                del config[i]
            break
    if action == "add" and not found:
        config.append(f"{key} = {value}\n")
    flags = os.O_CREAT | os.O_RDWR | os.O_TRUNC
    modes = stat.S_IWUSR | stat.S_IRUSR
    with os.fdopen(os.open(file_path, flags, modes), "w") as fp:
        fp.writelines(config)


def update_ograc_ini_conf(action, key, value):
    update_ini_conf(cfg.paths.ogracd_ini, action, key, value)


def update_cms_ini_conf(action, key, value):
    cms_ini = os.path.join(cfg.paths.cms_home, "cfg", "cms.ini")
    update_ini_conf(cms_ini, action, key, value)


def update_ogsql_config(action, key, value):
    ogsql_passwd = input()
    file_path = os.path.join(cfg.paths.action_dir, "ograc", "install_config.json")
    with open(file_path, 'r') as fp:
        json_data = json.load(fp)
        install_path = json_data['R_INSTALL_PATH'].strip()

    cmd = f"source ~/.bashrc && {install_path}/bin/ogencrypt -e PBKDF2"
    proc = subprocess.Popen(
        ["bash"], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    input_data = f"{cmd}\n{ogsql_passwd}\n{ogsql_passwd}\n"
    stdout, stderr = proc.communicate(input=input_data.encode(), timeout=60)
    if proc.returncode:
        raise OSError(f"Failed to encrypt password: {stderr.decode()}")

    lines = stdout.decode().split(os.linesep)
    cipher = lines[4].split(":")[1].strip()

    update_cmd = (f'source ~/.bashrc && ogsql / as sysdba -q -c '
                  f'"alter system set _sys_password=\'{cipher}\'"')
    ret, out, err = exec_popen(update_cmd)
    if ret or "Succeed" not in out:
        raise Exception(f"Update ogsql _sys_passwd failed: {err}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--component", dest="component",
                        choices=["cms", "ograc", "ograc_ini", "cms_ini", "ogsql"],
                        required=True)
    parser.add_argument("-a", "--action", dest="action",
                        choices=["del", "add", "update"], required=True)
    parser.add_argument("-k", "--key", dest="key", required=True)
    parser.add_argument("-v", "--value", dest="value", required=False)
    args = parser.parse_args()

    func_dict = {
        "ograc": update_ograc_conf,
        "ograc_ini": update_ograc_ini_conf,
        "cms": update_cms_conf,
        "cms_ini": update_cms_ini_conf,
        "ogsql": update_ogsql_config,
    }
    func_dict[args.component](args.action, args.key, args.value)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        sys.exit(traceback.format_exc(limit=-1))
