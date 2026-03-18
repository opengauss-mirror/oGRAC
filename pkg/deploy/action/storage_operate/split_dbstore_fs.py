#!/usr/bin/env python3
import json
import sys
import os
import pathlib
import traceback
import time
import shutil

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import cfg as _cfg
_paths = _cfg.paths

CUR_PATH, _ = os.path.split(os.path.abspath(__file__))
sys.path.append(str(pathlib.Path(CUR_PATH).parent))

from logic.storage_operate import StorageInf
from logic.common_func import exec_popen
from utils.client.rest_client import read_helper
from implement.upgrade_version_check import UpgradeVersionCheck
from om_log import LOGGER


class StorageFileSystemSplit(StorageInf):
    def __init__(self, ip, user_name, passwd, config):
        super(StorageFileSystemSplit, self).__init__((ip, user_name, passwd))
        self.config_info = json.loads(read_helper(config))
        self.storage_dbstor_fs = self.config_info.get("storage_dbstor_fs")
        self.storage_dbstor_page_fs = self.config_info.get("storage_dbstor_page_fs")
        self.metadata_logic_ip = self.config_info.get("metadata_logic_ip")
        self.namespace = self.config_info.get("cluster_name")
        self.vstore_id = 0

    @staticmethod
    def _move_files(src_path, dst_path):
        """Move all files from src_path to dst_path."""
        files = os.listdir(src_path)
        for file_name in files:
            temp_src = os.path.join(src_path, file_name)
            shutil.move(temp_src, dst_path)

    @staticmethod
    def _remove_mount_file_path(fs_name):
        """Remove dbstor filesystem mount directory."""
        mount_dir = os.path.join(_paths.remote_data, fs_name)
        rmdir_cmd = f"if [ -d {mount_dir} ];then rm -rf {mount_dir};fi"
        return_code, _, stderr = exec_popen(rmdir_cmd)
        if return_code:
            err_msg = f"Failed remove {mount_dir}, details:{stderr}"
            raise Exception(err_msg)

    def tailor_file_system(self):
        """Trim filesystem directories: mount, trim log/page fs, then unmount."""
        LOGGER.info("Start to tailor dbstor fs.")
        time.sleep(2)
        self.mount_file_system(self.storage_dbstor_fs, self.metadata_logic_ip)
        time.sleep(2)
        self.mount_file_system(self.storage_dbstor_page_fs, self.metadata_logic_ip)
        self.tailor_log_file_system()
        self.tailor_page_file_system()
        time.sleep(2)
        self._change_group_recursive()
        self.umount_file_system(self.storage_dbstor_fs)
        time.sleep(2)
        self.umount_file_system(self.storage_dbstor_page_fs)
        self._remove_mount_file_path(self.storage_dbstor_fs)
        self._remove_mount_file_path(self.storage_dbstor_page_fs)
        LOGGER.info("Success to tailor dbstor fs.")

    def tailor_log_file_system(self):
        """Trim log filesystem: remove page_pool_root_dir, flatten ulog_root_dir."""
        log_namespace_path = os.path.join(_paths.remote_data, self.storage_dbstor_fs, self.namespace)
        page_pool_root_dir = os.path.join(log_namespace_path, "page_pool_root_dir")
        ulog_root_dir = os.path.join(log_namespace_path, "ulog_root_dir")
        if os.path.exists(page_pool_root_dir):
            shutil.rmtree(page_pool_root_dir, ignore_errors=True)
        if os.path.exists(ulog_root_dir):
            self._move_files(ulog_root_dir, log_namespace_path)
            shutil.rmtree(ulog_root_dir)

    def tailor_page_file_system(self):
        """Trim page filesystem: remove namespace file, ulog_root_dir, flatten page_pool_root_dir."""
        page_namespace_path = os.path.join(_paths.remote_data, self.storage_dbstor_page_fs, self.namespace)
        namespace_file = os.path.join(page_namespace_path, self.namespace)
        page_pool_root_dir = os.path.join(page_namespace_path, "page_pool_root_dir")
        ulog_root_dir = os.path.join(page_namespace_path, "ulog_root_dir")
        if os.path.isfile(namespace_file):
            os.remove(namespace_file)
        if os.path.exists(ulog_root_dir):
            shutil.rmtree(ulog_root_dir)
        if os.path.exists(page_pool_root_dir):
            self._move_files(page_pool_root_dir, page_namespace_path)
            shutil.rmtree(page_pool_root_dir)

    def add_clone_share_client(self, share_id):
        data = {
            "ACCESSVAL": 1,
            "ALLSQUASH": 1,
            "ROOTSQUASH": 1,
            "PARENTID": share_id,
            "vstoreId": self.vstore_id,
            "NAME": "*"
        }
        self.add_nfs_client(data)

    def create_clone_share(self, clone_fs_id, share_path):
        """Create NFS share for the cloned filesystem."""
        clone_share_info = self.query_nfs_info(clone_fs_id, vstore_id=self.vstore_id)
        if clone_share_info:
            _share_id = clone_share_info[0].get("ID")
            self.delete_nfs_share(_share_id, vstore_id=self.vstore_id)
        data = {
            "SHAREPATH": f"/{share_path}/",
            "vstoreId": self.vstore_id,
            "FSID": clone_fs_id
        }
        share_id = self.create_nfs_share(data)
        return share_id

    def clear_dbstor_nfs_share(self, fs_id, clone_fs_id):
        """Delete NFS shares for the given filesystem IDs."""
        LOGGER.info("Begin to clear dbstor nfs share.fs_name:[%s], clone_fs_name:[%s]", self.storage_dbstor_fs,
                    self.storage_dbstor_page_fs)
        for _id in [fs_id, clone_fs_id]:
            share_info = self.query_nfs_info(_id, vstore_id=self.vstore_id)
            if share_info:
                _share_id = share_info[0].get("ID")
                self.delete_nfs_share(_share_id, vstore_id=self.vstore_id)
        LOGGER.info("Success to clear dbstor nfs share.")

    def pre_upgrade(self):
        LOGGER.info("Begin to check dbstor page fs info")
        page_file_system_info = self.query_filesystem_info(self.storage_dbstor_page_fs, vstore_id=self.vstore_id)
        if page_file_system_info:
            err_msg = "File system [%s] is exist." % self.storage_dbstor_page_fs
            LOGGER.error(err_msg)
            raise Exception(err_msg)
        LOGGER.info("Success to check dbstor page fs info")

    def upgrade(self):
        """Split dbstor filesystem: clone, split, create shares, trim dirs, cleanup."""
        fs_info = self.query_filesystem_info(self.storage_dbstor_fs, vstore_id=self.vstore_id)
        fs_id = fs_info.get("ID")

        clone_fs_info = self.query_filesystem_info(self.storage_dbstor_page_fs, vstore_id=self.vstore_id)
        if not clone_fs_info:
            clone_fs_info = self.create_clone_file_system(fs_id, self.storage_dbstor_page_fs, vstore_id=self.vstore_id)

        clone_fs_id = clone_fs_info.get("ID")
        split_status = clone_fs_info.get("SPLITSTATUS")
        split_enable = clone_fs_info.get("SPLITENABLE")

        if int(split_status) == 1 and split_enable == "false":
            self.split_clone_file_system(clone_fs_id)

        self.query_split_clone_file_system_process(self.storage_dbstor_page_fs, vstore_id=self.vstore_id)

        for _fs_id, _fs_name in [(fs_id, self.storage_dbstor_fs),
                                 (clone_fs_id, self.storage_dbstor_page_fs)]:
            _share_id = self.create_clone_share(_fs_id, _fs_name)
            self.add_clone_share_client(_share_id)

        self.tailor_file_system()

        self.clear_dbstor_nfs_share(_fs_id, clone_fs_id)

    def rollback(self):
        page_fs_info = self.query_filesystem_info(self.storage_dbstor_page_fs, vstore_id=self.vstore_id)
        if not page_fs_info:
            return
        file_system_id = page_fs_info.get("ID")
        self.delete_file_system(file_system_id)

    def _change_group_recursive(self):
        import importlib.util
        _action_dir = os.path.abspath(os.path.join(CUR_PATH, ".."))
        _spec = importlib.util.spec_from_file_location("_action_config", os.path.join(_action_dir, "config.py"))
        _ac = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(_ac)
        _env = _ac.load_env_defaults()
        ograc_user = _env["ograc_user"]
        ograc_group = _env["ograc_group"]
        dbstor_fs_path = os.path.join(_paths.remote_data, self.storage_dbstor_fs, self.namespace)
        dbstor_page_fs_path = os.path.join(_paths.remote_data, self.storage_dbstor_page_fs, self.namespace)
        LOGGER.info("Start change owner of %s and %s", dbstor_fs_path, dbstor_page_fs_path)
        cmd = f"chown -hR {ograc_user}:{ograc_group} {dbstor_fs_path} &&" \
              f" chown -hR {ograc_user}:{ograc_group} {dbstor_page_fs_path}"
        return_code, _, stderr = exec_popen(cmd)
        if return_code:
            err_msg = f"Failed chown {dbstor_fs_path}  {dbstor_page_fs_path}, details:{stderr}"
            LOGGER.info(err_msg)


def check_version():
    version_check = UpgradeVersionCheck()
    try:
        version_check.read_source_version_info()
    except Exception as _err:
        err_msg = 'obtain source version failed with error: %s', str(_err)
        raise Exception(err_msg) from _err
    return version_check.source_version.startswith("2.0.0")


def main():
    if not check_version():
        LOGGER.info("Current version is not 2.0.0, no need split file system")
        return
    action = sys.argv[1]
    config_file = sys.argv[2]
    if not os.path.exists(config_file):
        err_mgs = "Please input correct config file path."
        raise Exception(err_mgs)
    ip_addr = input()
    user_name = input()
    passwd = input()
    db_store_opt = StorageFileSystemSplit(ip_addr, user_name, passwd, config_file)
    db_store_opt.login()
    try:
        getattr(db_store_opt, action)()
    finally:
        db_store_opt.logout()


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        LOGGER.error("details:%s, traceback:%s", str(err), traceback.format_exc())
        exit(1)
