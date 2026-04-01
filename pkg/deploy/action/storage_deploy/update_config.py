import glob
import os
import re
import stat
import json
import grp
import configparser
import subprocess
import argparse
from pathlib import Path
import sys
import traceback
import getpass


DEPLOY_CONFIG = "/opt/ograc/config/deploy_param.json"
CUR_PATH = os.path.dirname(os.path.realpath(__file__))
ENV_FILE = str(Path(os.path.join(CUR_PATH, "env.sh")))


def _exec_popen(cmd, values=None):
    """
    subprocess.Popen in python2 and 3.
    :param cmd: commands need to execute
    :return: status code, standard output, error output
    """
    if not values:
        values = []
    bash_cmd = ["bash"]
    pobj = subprocess.Popen(bash_cmd, shell=False, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    pobj.stdin.write(cmd.encode())
    pobj.stdin.write(os.linesep.encode())
    for value in values:
        pobj.stdin.write(value.encode())
        pobj.stdin.write(os.linesep.encode())
    try:
        stdout, stderr = pobj.communicate(timeout=1800)
    except subprocess.TimeoutExpired as err_cmd:
        pobj.kill()
        return -1, "Time Out.", str(err_cmd)
    stdout = stdout.decode()
    stderr = stderr.decode()
    if stdout[-1:] == os.linesep:
        stdout = stdout[:-1]
    if stderr[-1:] == os.linesep:
        stderr = stderr[:-1]

    return pobj.returncode, stdout, stderr


def get_ogencrypt_passwd(passwd):
    file_path = "/opt/ograc/action/ograc/install_config.json"
    flags = os.O_RDONLY
    modes = stat.S_IWUSR | stat.S_IRUSR
    with os.fdopen(os.open(file_path, flags, modes), 'r') as fp:
        json_data = json.load(fp)
        install_path = json_data['R_INSTALL_PATH'].strip()
    cmd = "source ~/.bashrc && %s/bin/ogencrypt -e PBKDF2" % install_path
    values = [passwd, passwd]
    ret_code, stdout, stderr = _exec_popen(cmd, values)
    if ret_code:
        raise OSError("Failed to encrypt password of user [sys]."
                      " Error: %s" % (stderr + os.linesep + stderr))
    # Example of output:
    # Please enter password to encrypt:
    # *********
    # Please input password again:
    # *********
    # eg 'Cipher:         XXXXXXXXXXXXXXXXXXXXXXX'
    lines = stdout.split(os.linesep)
    cipher = lines[4].split(":")[1].strip()
    return cipher


def get_env_info(key):
    with open(ENV_FILE, encoding="utf-8") as _file:
        env_info = _file.read()
    pattern = rf'{key}="(.+?)"'
    match = re.search(pattern, env_info)
    return match.group(1)


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
        if section in config:
            if option in config[section]:
                config.remove_option(section, option)
    flags = os.O_CREAT | os.O_RDWR
    modes = stat.S_IWUSR | stat.S_IRUSR
    try:
        with os.fdopen(os.open(file_path, flags, modes), "w") as file_obj:
            file_obj.truncate(0)
            config.write(file_obj)
    except Exception as error:
        raise error


def read_deploy_conf(file_path=DEPLOY_CONFIG):
    with open(file_path, "r") as f:
        return json.loads(f.read())


def write_config_file(file_path, content):
    flags = os.O_RDWR | os.O_CREAT | os.O_TRUNC
    modes = stat.S_IRWXU | stat.S_IROTH | stat.S_IRGRP
    with os.fdopen(os.open(file_path, flags, modes), "w") as file_obj:
        file_obj.write(json.dumps(content))


def update_dbstor_conf(action, key, value=None):
    file_list = [
        "/mnt/dbdata/local/ograc/tmp/data/dbstor/conf/dbs/dbstor_config.ini",
        "/opt/ograc/dbstor/conf/dbs/dbstor_config.ini",
        "/opt/ograc/dbstor/conf/dbs/dbstor_config_tool_1.ini",
        "/opt/ograc/dbstor/conf/dbs/dbstor_config_tool_2.ini",
        "/opt/ograc/dbstor/conf/dbs/dbstor_config_tool_3.ini",
        "/opt/ograc/dbstor/tools/dbstor_config.ini",
        "/opt/ograc/cms/dbstor/conf/dbs/dbstor_config_tool_1.ini",
        "/opt/ograc/cms/dbstor/conf/dbs/dbstor_config_tool_2.ini",
        "/opt/ograc/cms/dbstor/conf/dbs/dbstor_config_tool_3.ini",
        "/opt/ograc/cms/dbstor/conf/dbs/dbstor_config.ini"
    ]
    opt_dbstor_config = "/opt/ograc/dbstor/tools/dbstor_config.ini"
    file_list.append(opt_dbstor_config)
    for file_path in file_list:
        if not os.path.exists(file_path):
            continue
        section = "CLIENT"
        modify_ini_file(file_path, section, key, action, value=value)


def update_ograc_conf(action, key, value):
    file_path = "/opt/ograc/ograc/cfg/ograc_config.json"
    config = read_deploy_conf(file_path=file_path)
    config["LOG_HOME"] = "/opt/ograc/log/ograc"
    write_config_file(file_path, config)


def update_cms_conf(action, key, value):
    deploy_config = read_deploy_conf()
    file_path = "/opt/ograc/cms/cfg/cms.json"
    if key == "cms_reserve":
        file_path = "/opt/ograc/backup/files/cms.json"
    config = read_deploy_conf(file_path=file_path)
    config["user"] = get_env_info("ograc_user")
    config["group"] = get_env_info("ograc_group")
    config["user_profile"] = "/home/ograc/.bashrc"
    config["user_home"] = "/home/ograc"
    config["share_logic_ip"] = deploy_config.get("share_logic_ip")
    write_config_file(file_path, config)


def update_ini_conf(file_path, action, key, value):
    with open(file_path, "r", encoding="utf-8") as fp:
        config = fp.readlines()
    for i, item in enumerate(config):
        if key in item:
            if action == "update":
                config[i] = f"{key} = {value}\n"
            if action == "del":
                del config[i]
            break
    if action == "add" and key not in str(config):
        config.append(f"{key} = {value}\n")
    flags = os.O_CREAT | os.O_RDWR | os.O_TRUNC
    modes = stat.S_IWUSR | stat.S_IRUSR
    with os.fdopen(os.open(file_path, flags, modes), "w") as file_obj:
        file_obj.writelines(config)


def update_ograc_ini_conf(action, key, value):
    file_path = "/mnt/dbdata/local/ograc/tmp/data/cfg/ogracd.ini"
    update_ini_conf(file_path, action, key, value)


def update_cms_ini_conf(action, key, value):
    file_path = "/opt/ograc/cms/cfg/cms.ini"
    update_ini_conf(file_path, action, key, value)


def update_ogsql_config(action, key, value):
    ogsql_passwd = input()
    encrypt_passwd = get_ogencrypt_passwd(ogsql_passwd)
    update_cmd = f'source ~/.bashrc && ogsql / as sysdba -q -c ' \
                 f'"alter system set _sys_password=\'{encrypt_passwd}\'"'
    ret_code, stdout, stderr = _exec_popen(update_cmd)
    stderr = str(stderr)
    stderr.replace(ogsql_passwd, "****")
    if ret_code:
        raise OSError("Failed to encrypt password of user [sys]."
                      " Error: %s" % (stderr + os.linesep + stderr))
    if "Succeed" not in stdout:
        raise Exception("Update ogsql _sys_passwd failed")

def main():
    update_parse = argparse.ArgumentParser()
    update_parse.add_argument("-c", "--component", dest="component",
                              choices=["dbstor", "cms", "ograc", "ograc_ini", "cms_ini", "ogsql"],
                              required=True)
    update_parse.add_argument("-a", "--action", dest="action", choices=["del", "add", "update"],
                              required=True)
    update_parse.add_argument("-k", "--key", dest="key", required=True)
    update_parse.add_argument("-v", "--value", dest="value", required=False)
    args = update_parse.parse_args()
    component = args.component
    action = args.action
    key = args.key
    value = args.value
    func_dict = {
        "dbstor": update_dbstor_conf,
        "ograc": update_ograc_conf,
        "ograc_ini": update_ograc_ini_conf,
        "cms": update_cms_conf,
        "cms_ini": update_cms_ini_conf,
        "ogsql": update_ogsql_config,
    }
    func_dict.get(component)(action, key, value)


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        exit(str(traceback.format_exc(limit=-1)))
