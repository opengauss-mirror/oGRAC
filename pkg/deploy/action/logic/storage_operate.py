#!/usr/bin/env python3
"""Storage operation interface."""

import os
import sys
import time

CUR_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, CUR_PATH)

from utils.client.rest_client import RestClient
from utils.config.rest_constant import Constant
from logic_refactored.common_func import exec_popen
from utils.client.response_parse import ResponseParse
from om_log import REST_LOG as LOG

from config import cfg as _cfg
_paths = _cfg.paths


class StorageInf(object):
    def __init__(self, login_tuple):
        self.ip, self.user_name, self.passwd = login_tuple
        self.url_prefix = Constant.HTTPS + self.ip + ":" + Constant.PORT
        self.rest_client = RestClient(login_tuple)

    @staticmethod
    def handle_error_msg(err_msg):
        LOG.error(err_msg)
        raise Exception(err_msg)

    @staticmethod
    def umount_file_system(fs_name):
        mount_dir = os.path.join(_paths.remote_data, fs_name)
        umount_cmd = f"umount {mount_dir}"
        check_mount = f"mountpoint {mount_dir}"
        retry_times = 3
        err_msg = f"Failed umount {mount_dir}, details:%s"
        while retry_times:
            return_code, stdout, stderr = exec_popen(check_mount)
            if return_code:
                LOG.info("%s has not been mounted.", mount_dir)
                return
            return_code, stdout, stderr = exec_popen(umount_cmd)
            if return_code:
                time.sleep(30)
                retry_times -= 1
                _err_msg = err_msg % stderr + f"remain retry times:{retry_times}"
                LOG.error(_err_msg)
                continue
            else:
                LOG.info("Umount %s success", mount_dir)
                return
        else:
            raise Exception(err_msg % stderr)

    @staticmethod
    def mount_file_system(fs_name, logic_ip, prefix=None, params=""):
        mount_dir = os.path.join(_paths.remote_data, fs_name) if prefix is None \
            else os.path.join(_paths.remote_data, f"{prefix}_{fs_name}")
        mount_cmd = f"mount -t nfs {params} {logic_ip}:/{fs_name} " + mount_dir
        mkdir_cmd = f"if [ ! -d {mount_dir} ];then mkdir -p {mount_dir};fi"
        return_code, _, stderr = exec_popen(mkdir_cmd)
        if return_code:
            err_msg = f"Failed mkdir {mount_dir}, details:{stderr}"
            raise Exception(err_msg)
        check_mount = f"mountpoint {mount_dir}"
        return_code, _, stderr = exec_popen(check_mount)
        err_msg = f"Failed mount {mount_dir}, details:%s"
        if return_code:
            retry_times = 3
            while retry_times:
                return_code, stdout, stderr = exec_popen(mount_cmd)
                if return_code:
                    time.sleep(30)
                    retry_times -= 1
                    _err_msg = err_msg % stderr + f"retry times:{retry_times}/3"
                    LOG.error(_err_msg)
                    continue
                else:
                    LOG.info("Mount %s success", mount_dir)
                    return
            else:
                raise Exception(err_msg % stderr)

    @classmethod
    def result_parse(cls, err_msg, res):
        err_msg = err_msg + ", Detail:[%s]%s.Suggestion:%s"
        result = ResponseParse(res)
        status_code, error_code, error_des = result.get_res_code()
        if status_code != 200 or error_code != 0:
            err_msg = err_msg % (status_code, error_code, error_des)
            cls.handle_error_msg(err_msg)
        rsp_code, rsp_result, rsp_data = result.get_rsp_data()
        error_code = rsp_result.get('code')
        if rsp_code != 0 or error_code != 0:
            error_des = rsp_result.get('description')
            error_sgt = rsp_result.get('suggestion')
            err_msg = err_msg % (error_code, error_des, error_sgt)
            cls.handle_error_msg(err_msg)
        return rsp_data

    @classmethod
    def omstask_result_parse(cls, err_msg, res):
        err_msg = err_msg + ", Detail:[%s]%s.Suggestion:%s"
        result = ResponseParse(res)
        rsp_code, rsp_result, rsp_data = result.get_omtask_rsp_data()
        if rsp_code != 0 or (rsp_result.get('code') and rsp_result.get('code') != 0):
            error_des = rsp_result.get('description')
            error_sgt = rsp_result.get('suggestion')
            err_msg = err_msg % (rsp_result.get('code'), error_des, error_sgt)
            cls.handle_error_msg(err_msg)
        return rsp_data

    def login(self):
        LOG.info("login DM start")
        try:
            self.rest_client.login()
        except Exception as _err:
            err_msg = "Login DM[float ip:%s] failed, details: %s " % (self.ip, str(_err))
            self.handle_error_msg(err_msg)
        LOG.info("Login DM success.")

    def logout(self):
        try:
            self.rest_client.logout()
        except Exception as err:
            LOG.info(str(err))

    def query_filesystem_info(self, fs_name, vstore_id=0) -> dict:
        query_url = Constant.CREATE_FS.format(deviceId=self.rest_client.device_id)
        url = query_url + f"?filter=NAME:{fs_name}&vstoreId={vstore_id}"
        res = self.rest_client.normal_request(url, "get")
        err_msg = f"Failed to query fs{fs_name} id"
        data = self.result_parse(err_msg, res)
        for _fs_info in data:
            if _fs_info.get("NAME") == fs_name:
                return _fs_info
        return {}

    def query_storage_pool_info(self, pool_id):
        LOG.info("Query storage pool info start, pool_id:[%s]", pool_id)
        url = Constant.QUERY_POOL.format(deviceId=self.rest_client.device_id) + f"?filter=ID:{pool_id}"
        res = self.rest_client.normal_request(url, "get")
        err_msg = f"Failed to query pool  id:[{pool_id}]"
        resp_data = self.result_parse(err_msg, res)
        return resp_data

    def query_vstore_count(self, vstore_id):
        url = Constant.QUERY_VSTORE.format(deviceId=self.rest_client.device_id) + f"?filter=ID:{vstore_id}"
        res = self.rest_client.normal_request(url, "get")
        err_msg = f"Failed to query vstore id:[{vstore_id}]"
        rsp_data = self.result_parse(err_msg, res)
        return rsp_data

    def query_vstore_info(self, vstore_id):
        url = Constant.DELETE_VSTORE.format(deviceId=self.rest_client.device_id, id=vstore_id)
        res = self.rest_client.normal_request(url, "get")
        err_msg = f"Failed to query vstore info:[{vstore_id}]"
        rsp_data = self.result_parse(err_msg, res)
        return rsp_data

    def query_rollback_snapshots_process(self, fs_name, vstore_id=0):
        query_url = Constant.QUERY_ROLLBACK_SNAPSHOT_PROCESS.format(
            deviceId=self.rest_client.device_id, fs_name=fs_name)
        url = query_url + f"&&vstoreId={vstore_id}"
        res = self.rest_client.normal_request(url, 'get')
        err_msg = f"Failed to query fs[{fs_name}] rollback snapshot process."
        rsp_data = self.result_parse(err_msg, res)
        return rsp_data

    def query_split_clone_file_system_process(self, fs_name, vstore_id=0):
        while True:
            clone_fs_info = self.query_filesystem_info(fs_name, vstore_id)
            progress = clone_fs_info.get("SPLITPROGRESS")
            split_status = clone_fs_info.get("SPLITSTATUS")
            split_enable = clone_fs_info.get("SPLITENABLE")
            if 0 <= int(progress) < 100:
                LOG.info("Split clone fs[%s] progress:%s", fs_name, progress)
                time.sleep(10)
                continue
            if progress == "-1" and split_enable == "false":
                LOG.info("Split clone fs[%s] success.", fs_name)
                return
            if split_status == 4:
                err_msg = "Split clone fs[%s] failed" % fs_name
                raise Exception(err_msg)

    def query_nfs_info(self, fs_id, vstore_id=0):
        query_url = Constant.NFS_SHARE_QUERY.format(deviceId=self.rest_client.device_id)
        url = query_url + f"?filter=FSID:{fs_id}&vstoreId={vstore_id}"
        res = self.rest_client.normal_request(url, "get")
        err_msg = f"Failed to query NFS share id of fs{fs_id}"
        return self.result_parse(err_msg, res)

    def query_nfs_share_auth_client(self, nfs_share_id, vstore_id=0):
        query_url = Constant.NFS_SHARE_ADD_CLIENT.format(deviceId=self.rest_client.device_id)
        url = query_url + f"?filter=PARENTID:{nfs_share_id}&vstoreId={vstore_id}&range=[0-1]"
        res = self.rest_client.normal_request(url, "get")
        err_msg = f"Failed to query nfs share auth client, nfs_share_id:%s" % nfs_share_id
        return self.result_parse(err_msg, res)

    def query_logical_port_info(self, ip_addr, vstore_id=None):
        query_url = Constant.QUERY_LOGIC_PORT_INFO.format(deviceId=self.rest_client.device_id)
        if vstore_id:
            url = query_url + f"?filter=IPV4ADDR:{ip_addr}&range=[0-100]&vstoreId={vstore_id}"
        else:
            url = query_url + f"?filter=IPV4ADDR:{ip_addr}&range=[0-100]"
        res = self.rest_client.normal_request(url, "get")
        err_msg = "Failed to query lf info"
        return self.result_parse(err_msg, res)

    def query_logical_port_info_by_vstore_id(self, vstore_id="0"):
        query_url = Constant.QUERY_LOGIC_PORT_INFO.format(deviceId=self.rest_client.device_id)
        url = query_url + f"?vstoreId={vstore_id}"
        res = self.rest_client.normal_request(url, "get")
        err_msg = "Failed to query lf info"
        return self.result_parse(err_msg, res)

    def create_file_system(self, data):
        url = Constant.CREATE_FS.format(deviceId=self.rest_client.device_id)
        res = self.rest_client.normal_request(url, "post", data=data)
        err_msg = f"Failed to create file system, data:{data}"
        rsp_data = self.result_parse(err_msg, res)
        LOG.info("Create file system succees, data:%s", data)
        return rsp_data.get("ID")

    def create_clone_file_system(self, parent_id, clone_fs_name, vstore_id=0):
        LOG.info("Begin to clone fs id[%s], new fs[%s], vstore id [%s]", parent_id, clone_fs_name, vstore_id)
        url = Constant.CREATE_CLONE_FS.format(deviceId=self.rest_client.device_id)
        data = {"NAME": clone_fs_name, "PARENTFILESYSTEMID": parent_id, "vstoreId": vstore_id}
        res = self.rest_client.normal_request(url, "post", data=data)
        err_msg = f"Failed to clone fs[id:{parent_id}], clone fs name:{clone_fs_name} "
        rsp_data = self.result_parse(err_msg, res)
        LOG.info("Clone file system success")
        return rsp_data

    def create_file_system_snapshot(self, name, fs_id, vstore_id=0):
        data = {'NAME': name, 'PARENTID': fs_id, 'vstoreId': vstore_id, 'PARENTTYPE': 40}
        url = Constant.CREATE_FSSNAPSHOT.format(deviceId=self.rest_client.device_id)
        res = self.rest_client.normal_request(url, "post", data=data)
        err_msg = f"Failed to create fs snapshot, fs_id:[%s], name:[%s]" % (fs_id, name)
        rsp_data = self.result_parse(err_msg, res)
        return rsp_data

    def split_clone_file_system(self, clone_fs_id, action=1, vstore_id=0):
        LOG.info("Begin to split clone fs[id:%s]", clone_fs_id)
        url = Constant.SPLIT_CLONE_FS.format(deviceId=self.rest_client.device_id)
        data = {"ID": clone_fs_id, "action": action, "vstoreId": vstore_id}
        res = self.rest_client.normal_request(url, "put", data=data)
        err_msg = f"Failed to split clone fs[id:{clone_fs_id}]"
        self.result_parse(err_msg, res)
        LOG.info("Success to split clone fs[id:%s]", clone_fs_id)

    def rollback_file_system_snapshot(self, snapshot_id, vstore_id=0):
        data = {'ID': snapshot_id, 'vstoreId': vstore_id}
        url = Constant.ROLLBACK_SNAPSHOT.format(deviceId=self.rest_client.device_id)
        res = self.rest_client.normal_request(url, "put", data=data)
        err_msg = f"Failed to rollback snapshot, snapshot_id:[%s]" % snapshot_id
        rsp_data = self.result_parse(err_msg, res)
        return rsp_data

    def query_file_system_snapshot_info(self, snapshot_id):
        url = (Constant.CREATE_FSSNAPSHOT + "/{id}").format(
            deviceId=self.rest_client.device_id, id=snapshot_id)
        res = self.rest_client.normal_request(url, "get")
        err_msg = f"Failed to query snapshot info, snapshot_id:[%s]" % snapshot_id
        rsp_data = self.result_parse(err_msg, res)
        return rsp_data

    def delete_file_system_snapshot(self, snapshot_id):
        url = (Constant.CREATE_FSSNAPSHOT + "/{id}").format(
            deviceId=self.rest_client.device_id, id=snapshot_id)
        res = self.rest_client.normal_request(url, "delete")
        err_msg = f"Failed to delete snapshot, snapshot_id:[%s]" % snapshot_id
        rsp_data = self.result_parse(err_msg, res)
        return rsp_data

    def create_nfs_share(self, data):
        url = Constant.NFS_SHARE_ADD.format(deviceId=self.rest_client.device_id)
        res = self.rest_client.normal_request(url, "post", data=data)
        err_msg = f"Failed to create nfs share, data:{data}"
        rsp_data = self.result_parse(err_msg, res)
        LOG.info("Create nfs success, data:%s", data)
        return rsp_data.get("ID")

    def add_nfs_client(self, data):
        url = Constant.NFS_SHARE_ADD_CLIENT.format(deviceId=self.rest_client.device_id)
        res = self.rest_client.normal_request(url, "post", data=data)
        err_msg = f'Failed to create nfs share, data:{data}'
        rsp_data = self.result_parse(err_msg, res)
        LOG.info("Add nfs client success, data:%s", data)
        return rsp_data.get("ID")

    def open_nfs_service(self, vstore_id):
        LOG.info("Begin to open nfs 4.0 and 4.1 configer of vstore[%s]", vstore_id)
        url = Constant.NFS_SERVICE.format(deviceId=self.rest_client.device_id)
        data = {"vstoreId": vstore_id, "SUPPORTV4": True, "SUPPORTV41": True}
        res = self.rest_client.normal_request(url, "put", data=data)
        err_msg = f"Failed to open vstore{vstore_id} nfs service"
        self.result_parse(err_msg, res)
        LOG.info("Open nfs 4.0 and 4.1 configer success.")

    def query_nfs_service(self, vstore_id="0"):
        LOG.info("Begin to query nfs 4.0 and 4.1 configer of vstore[%s]", vstore_id)
        url = Constant.NFS_SERVICE.format(deviceId=self.rest_client.device_id)
        url += f"?vstoreId={vstore_id}"
        res = self.rest_client.normal_request(url, "get")
        err_msg = f"Query to open vstore{vstore_id} nfs service"
        data = self.result_parse(err_msg, res)
        LOG.info("Query nfs 4.0 and 4.1 configer success.")
        return data

    def delete_nfs_share(self, nfs_share_id, vstore_id=0):
        LOG.info("Begin to del nfs share, id[%s]", nfs_share_id)
        del_share_url = Constant.NFS_SHARE_DELETE.format(
            deviceId=self.rest_client.device_id, id=nfs_share_id)
        url = del_share_url + f"?vstoreId={vstore_id}"
        res = self.rest_client.normal_request(url, "delete")
        err_msg = f"Failed to delete {nfs_share_id} nfs share"
        self.result_parse(err_msg, res)
        LOG.info("Delete id[%s] nfs share success", nfs_share_id)

    def delete_file_system(self, fs_id):
        LOG.info("Begin to del fs by id[%s]", fs_id)
        url = Constant.DELETE_FS.format(deviceId=self.rest_client.device_id, id=fs_id)
        res = self.rest_client.normal_request(url, "delete")
        err_msg = f"Failed to delete {fs_id} fs"
        self.result_parse(err_msg, res)
        LOG.info("Delete id[%s] fs success", fs_id)

    def delete_fs_cdp_schedule(self, fs_id, cdp_id, cdp_name, vstore_id):
        LOG.info("Begin to delete cdp schedule by id[%s]", cdp_id)
        url = Constant.DELETE_FS_CDP_SCHEDULE.format(deviceId=self.rest_client.device_id)
        data = {"ID": fs_id, "TIMINGSNAPSHOTSCHEDULEID": cdp_id,
                "scheduleName": cdp_name, "vstoreId": vstore_id}
        res = self.rest_client.normal_request(url, "delete", data=data)
        err_msg = f"Failed to delete {cdp_id} cdp schedule"
        self.result_parse(err_msg, res)
        LOG.info("Delete id[%s] cdp schedule success", cdp_id)
