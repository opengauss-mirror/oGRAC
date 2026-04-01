#!/usr/bin/env python3
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from config import cfg as _cfg
_paths = _cfg.paths

from logic.storage_operate import StorageInf
from utils.config.rest_constant import Constant, RepFileSystemNameRule
from logic.common_func import exec_popen
from logic.common_func import retry
from om_log import LOGGER as LOG
from get_config_info import get_env_info


CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))


class RemoteStorageOPT(object):
    def __init__(self, storage_operate: StorageInf, remote_device_id: str):
        self.storage_opt = storage_operate
        self.rest_client = self.storage_opt.rest_client
        self.remote_device_id = remote_device_id
        self.run_user = get_env_info("ograc_user")

    def query_remote_storage_vstore_info(self, vstore_id: str) -> list:
        LOG.info("Start to query remote storage vstore info, vstoreId[%s]", vstore_id)
        url = Constant.REMOTE_EXECUTE
        data = {
            "device_id": self.remote_device_id,
            "url": Constant.CREATE_VSTORE.replace("{deviceId}", "xxx"),
            "method": "GET",
            "body": {
                "ID": f"{vstore_id}"
            }
        }
        res = self.rest_client.normal_request(url, data=data, method="post")
        err_msg = "Failed to query remote storage vstore info,vstoreId[%s]" % vstore_id
        rsp_data = StorageInf.omstask_result_parse(err_msg, res)
        LOG.info("Success to query remote storage vstore info, vstoreId[%s]", vstore_id)
        return rsp_data

    def query_remote_storage_system_info(self) -> dict:
        LOG.info("Start to query remote storage system info.")
        url = Constant.REMOTE_EXECUTE
        data = {
            "device_id": self.remote_device_id,
            "url": Constant.QUERY_SYSTEM_INFO.replace("{deviceId}", "xxx"),
            "method": "GET",
            "body": {}
        }
        res = self.rest_client.normal_request(url, data=data, method="post")
        err_msg = "Failed to query remote storage system info"
        rsp_data = StorageInf.omstask_result_parse(err_msg, res)
        LOG.info("Success to query remote storage system info.")
        return rsp_data

    def query_remote_storage_vstore_filesystem_num(self, vstore_id):
        url = Constant.REMOTE_EXECUTE
        remote_url = Constant.QUERY_FILE_SYSTEM_NUM
        data = {
            "device_id": self.remote_device_id,
            "url": remote_url.replace("{deviceId}", "xxx"),
            "method": "GET",
            "body": {
                "vstoreId": vstore_id
            }
        }
        res = self.rest_client.normal_request(url, data=data, method="post")
        err_msg = "Failed to query remote storage filesystem num,vstoreId[%s]" % vstore_id
        rsp_data = StorageInf.omstask_result_parse(err_msg, res)
        LOG.info("Success to query remote storage filesystem num, vstoreId[%s]", vstore_id)
        return rsp_data

    def query_remote_filesystem_info(self, fs_name: str, vstore_id: str):
        url = Constant.REMOTE_EXECUTE
        data = {
            "device_id": self.remote_device_id,
            "url": Constant.CREATE_FS.replace("{deviceId}", "xxx") + "?filter=NAME::%s" % fs_name,
            "method": "GET",
            "body": {
                "vstoreId": vstore_id
            }
        }
        res = self.rest_client.normal_request(url, data=data, method="post")
        err_msg = "Failed to query remote filesystem[%s] info, vstore_id[%s]" % (fs_name, vstore_id)
        rsp_data = StorageInf.omstask_result_parse(err_msg, res)
        fs_info = dict()
        for filesystem_info in rsp_data:
            if filesystem_info.get("NAME") == fs_name:
                fs_info = filesystem_info
                break
        LOG.info("Success to query remote filesystem[%s] info, vstore_id[%s]", fs_name, vstore_id)
        return fs_info

    def query_remote_storage_pool_info(self, pool_id: str) -> dict:
        """Query remote storage pool info."""
        url = Constant.REMOTE_EXECUTE
        remote_url = Constant.QUERY_POOL
        data = {
            "device_id": self.remote_device_id,
            "url": remote_url.replace("{deviceId}", "xxx"),
            "method": "GET",
            "body": {
                "ID": pool_id
            }
        }
        res = self.rest_client.normal_request(url, data=data, method="post")
        err_msg = "Failed to query remote storage pool info,poolId[%s]" % pool_id
        rsp_data = StorageInf.omstask_result_parse(err_msg, res)
        LOG.info("Success to query remote storage pool info, poolId[%s]", pool_id)
        return rsp_data


class KmcResolve(object):
    @staticmethod
    def kmc_resolve_password(mode, plain_text):
        """Encrypt or decrypt password via KMC."""
        run_user = get_env_info("ograc_user")
        resolve_file_path = os.path.join(CURRENT_PATH, "../../ograc_common/crypte_adapter.py")
        cmd = "su -s /bin/bash - %s -c \"export LD_LIBRARY_PATH=%s:${LD_LIBRARY_PATH} " \
              "&& echo -e %s | python3 -B %s %s\"" % (run_user, _paths.dbstor_lib, plain_text, resolve_file_path, mode)
        return_code, output, stderr = exec_popen(cmd)
        if return_code == 1:
            raise Exception("resolve password failed.")
        return output


class DRDeployCommon(object):
    def __init__(self, storage_operate: StorageInf):
        self.storage_opt = storage_operate
        self.device_id = self.storage_opt.rest_client.device_id
        self.rest_client = self.storage_opt.rest_client

    def query_storage_system_info(self) -> dict:
        LOG.info("Start to query storage system info.")
        url = Constant.QUERY_SYSTEM_INFO.format(deviceId=self.device_id)
        res = self.rest_client.normal_request(url, "get")
        err_msg = "Failed to query storage system info"
        rsp_data = StorageInf.result_parse(err_msg, res)
        LOG.info("Success to query storage system info.")
        return rsp_data

    def query_remote_device_info(self, remote_device_id=None) -> list:
        LOG.info("Start to query remote device info.")
        url = Constant.QUERY_REMOTE_DEVICE_INFO.format(deviceId=self.device_id)
        if remote_device_id:
            url = url + f"/{remote_device_id}"
        res = self.rest_client.normal_request(url, "get")
        err_msg = "Failed to query remote device info"
        rsp_data = StorageInf.result_parse(err_msg, res)
        LOG.info("Success to query remote device info")
        return rsp_data

    def query_vstore_filesystem_num(self, vstore_id: str):
        LOG.info("Start to query vstore file system num.")
        url = Constant.QUERY_FILE_SYSTEM_NUM.format(deviceId=self.device_id)
        data = {"vstoreId": vstore_id}
        res = self.rest_client.normal_request(url, data=data, method="get")
        err_msg = "Failed to query vstore file system num"
        rsp_data = StorageInf.result_parse(err_msg, res)
        LOG.info("Success to query vstore file system num.")
        return rsp_data

    def query_license_info(self):
        LOG.info("Start to query license info.")
        url = Constant.QUERY_LICENSE_FEATURE.format(deviceId=self.device_id)
        res = self.rest_client.normal_request(url, "get")
        err_msg = "Failed to query license info"
        rsp_data = StorageInf.result_parse(err_msg, res)
        LOG.info("Success to query license info.")
        return rsp_data

    @retry(retry_times=3, wait_times=20, log=LOG, task="query_hyper_metro_domain_info")
    def query_hyper_metro_domain_info(self, domain_id=None):
        LOG.info("Start to query hyper metro domain info.")
        url = Constant.HYPER_METRO_DOMAIN.format(deviceId=self.device_id)
        if domain_id:
            url = url + "/" + domain_id
        res = self.rest_client.normal_request(url, method="get")
        err_msg = "Failed to query hyper metro domain info"
        rsp_data = StorageInf.result_parse(err_msg, res)
        LOG.info("Success to query hyper metro domain info.")
        return rsp_data

    def query_hyper_metro_vstore_pair_info(self, vstore_pair_id=None) -> dict:
        LOG.info("Start to query hyper metro vstore pair info.")
        url = Constant.HYPER_METRO_VSTORE_PAIR.format(deviceId=self.device_id)
        if vstore_pair_id:
            url = url + "/" + vstore_pair_id
        res = self.rest_client.normal_request(url, "get")
        err_msg = "Failed to query hyper metro vstore pair info"
        rsp_data = StorageInf.result_parse(err_msg, res)
        LOG.info("Success to query hyper metro vstore pair info.")
        return rsp_data

    def query_hyper_metro_filesystem_pair_info(self, filesystem_id: str) -> list:
        url = (Constant.QUERY_HYPER_METRO_FILE_SYSTEM_PAIR + "?ASSOCIATEOBJTYPE=40&ASSOCIATEOBJID={fs_id}"). \
            format(deviceId=self.device_id, fs_id=filesystem_id)
        res = self.rest_client.normal_request(url, "get")
        err_msg = "Failed to query hyper metro file system pair info"
        rsp_data = StorageInf.result_parse(err_msg, res)
        return rsp_data

    def query_hyper_metro_filesystem_count_info(self, vstore_id: str) -> list:
        url = (Constant.QUERY_HYPER_METRO_FILE_SYSTEM_COUNT).format(deviceId=self.device_id)
        data = {"vstoreId": vstore_id}
        res = self.rest_client.normal_request(url, data=data, method="get")
        err_msg = "Failed to query hyper metro file system pair count info"
        rsp_data = StorageInf.result_parse(err_msg, res)
        return rsp_data

    def query_ulog_filesystem_info_list(self, vstore_id: str) -> list:
        url = Constant.HYPER_METRO_FILESYSTEM_PAIR.format(deviceId=self.device_id)
        data = {"vstoreId": vstore_id}
        res = self.rest_client.normal_request(url, data=data, method="get")
        err_msg = "Failed to query ulog file system pair info list"
        rsp_data = StorageInf.result_parse(err_msg, res)
        return rsp_data

    def query_hyper_metro_filesystem_pair_info_by_pair_id(self, pair_id: str) -> dict:
        url = Constant.DELETE_HYPER_METRO_PAIR.format(deviceId=self.device_id, id=pair_id)
        res = self.rest_client.normal_request(url, "get")
        err_msg = "Failed to query hyper metro filesystem pair info by pair id[%s]" % pair_id
        rsp_data = StorageInf.result_parse(err_msg, res)
        return rsp_data

    def query_remote_replication_pair_info(self, filesystem_id: str) -> list:
        url = (Constant.QUERY_REPLICATION_FILE_SYSTEM_PAIR + "?ASSOCIATEOBJTYPE=40&ASSOCIATEOBJID={fs_id}") \
            .format(deviceId=self.device_id, fs_id=filesystem_id)
        res = self.rest_client.normal_request(url, "get")
        err_msg = "Failed to query remote replication filesystem[%s] info" % filesystem_id
        rsp_data = StorageInf.result_parse(err_msg, res)
        return rsp_data

    def query_remote_replication_pair_info_by_pair_id(self, pair_id: str) -> dict:
        url = Constant.REMOTE_REPLICATION_FILESYSTEM_PAIR_OPT.format(deviceId=self.device_id, id=pair_id)
        res = self.rest_client.normal_request(url, "get")
        err_msg = "Failed to query remote replication file system info by pair id[%s]" % pair_id
        rsp_data = StorageInf.result_parse(err_msg, res)
        return rsp_data

    def query_filesystem_for_replication(self, remote_device_id: str) -> list:
        LOG.info("Start to query filesystem for replication info.")
        url = (Constant.QUERY_FILESYSTEM_FOR_REPLICATION + "?rmtDeviceId={remote_device_id}&RSSType=24"). \
            format(deviceId=self.device_id, remote_device_id=remote_device_id)
        res = self.rest_client.normal_request(url, "get")
        err_msg = "Failed to query filesystem for replication info"
        rsp_data = StorageInf.result_parse(err_msg, res)
        LOG.info("Success to query filesystem for replication info.")
        return rsp_data

    def query_omtask_process(self, task_id: str, timeout: int) -> None:
        LOG.info("Start to query task[%s] process", task_id)
        url = Constant.QUERY_TASK_PROCESS.format(id=task_id)
        while timeout:
            res = self.rest_client.normal_request(url, "get")
            err_msg = "Failed to query task[%s] process" % task_id
            rsp_data = StorageInf.omstask_result_parse(err_msg, res)
            task_status = rsp_data.get("taskStatus")
            name = rsp_data.get("name")
            description = rsp_data.get("description")
            current_step_index = description.get("currentStepIndex")
            step_count = description.get("stepCount")
            LOG.info("Task[%s] status [%s], running process[%s/%s]",
                     name, task_status, current_step_index, step_count)
            if task_status == "success":
                break
            if task_status in ["executing", "wait"]:
                time.sleep(10)
                timeout -= 10
                continue
            else:
                err_msg = "Failed to create filesystem pair"
                LOG.error(err_msg)
                raise Exception(err_msg)

    @retry(retry_times=3, wait_times=20, log=LOG, task="create_filesystem_hyper_metro_domain")
    def create_filesystem_hyper_metro_domain(self, dev_name, dev_esn, dev_id, domain_name):
        LOG.info("Start to create filesystem hyper metro domain.")
        data = {
            "NAME": domain_name, "workMode": "1", "isShareAuthenticationSync": False, "DESCRIPTION": "",
            "REMOTEDEVICES": [{"devId": dev_id, "devESN": dev_esn, "devName": dev_name}]
        }
        url = Constant.HYPER_METRO_DOMAIN.format(deviceId=self.device_id)
        res = self.rest_client.normal_request(url, data=data, method="post")
        err_msg = "Failed to create filesystem hyper metro domain"
        rsp_data = StorageInf.result_parse(err_msg, res)
        LOG.info("Success to create filesystem hyper metro domain.")
        return rsp_data

    @retry(retry_times=3, wait_times=20, log=LOG, task="create_hyper_metro_vstore_pair")
    def create_hyper_metro_vstore_pair(self, domain_id, local_vstore_id, remote_vstore_id):
        LOG.info("Start to create hyper metro vstore pair.")
        data = {
            "DOMAINID": domain_id, "LOCALVSTOREID": local_vstore_id, "REMOTEVSTOREID": remote_vstore_id,
            "REPTYPE": "1", "PREFERREDMODE": "0", "isNetworkSync": False
        }
        url = Constant.HYPER_METRO_VSTORE_PAIR.format(deviceId=self.device_id)
        res = self.rest_client.normal_request(url, data=data, method="post")
        err_msg = "Failed to create hyper metro vstore pair"
        rsp_data = StorageInf.result_parse(err_msg, res)
        LOG.info("Success to create hyper metro vstore pair.")
        return rsp_data

    @retry(retry_times=3, wait_times=20, log=LOG, task="create_hyper_metro_filesystem_pair")
    def create_hyper_metro_filesystem_pair(self, filesystem_id, pool_id, vstore_pair_id):
        LOG.info("Start to create hyper metro filesystem pair.")
        data = {"vstorePairID": vstore_pair_id, "remoteStoragePoolId": pool_id, "objs": [filesystem_id]}
        url = Constant.CREATE_HYPER_METRO_FILESYSTEM_PAIR
        res = self.rest_client.normal_request(url, data=data, method="post")
        err_msg = "Failed to create hyper metro filesystem pair"
        rsp_data = StorageInf.omstask_result_parse(err_msg, res)
        LOG.info("Success to create hyper metro filesystem pair.")
        return rsp_data

    @retry(retry_times=3, wait_times=20, log=LOG, task="modify_hyper_metro_filesystem_pair_sync_speed")
    def modify_hyper_metro_filesystem_pair_sync_speed(self, vstore_pair_id, speed):
        LOG.info("Start to modify hyper metro filesystem pair speed to [%d].", speed)
        data = {"ID": vstore_pair_id, "SPEED": speed}
        url = Constant.HYPER_METRO_FILESYSTEM_PAIR.format(deviceId=self.device_id)
        res = self.rest_client.normal_request(url, data=data, method="put")
        err_msg = "Failed to modify hyper metro filesystem pair speed"
        StorageInf.result_parse(err_msg, res)
        LOG.info("Start to modify hyper metro filesystem pair speed.")

    @retry(retry_times=3, wait_times=20, log=LOG, task="create_remote_replication_filesystem_pair")
    def create_remote_replication_filesystem_pair(self, **pair_args):
        local_fs_id = pair_args.get("local_fs_id")
        remote_device_id = pair_args.get("remote_device_id")
        speed = pair_args.get("speed")
        remote_pool_id = pair_args.get("remote_pool_id")
        remote_name_rule = pair_args.get("remote_name_rule")
        name_suffix = pair_args.get("name_suffix")
        LOG.info("Start to create remote replication filesystem[%s] pair.", local_fs_id)
        data = {
            "type": "filesystem",
            "replication": {
                "replicationModel": 2, "remoteStorageId": remote_device_id, "speed": speed,
                "recoveryPolicy": 2, "remoteStoragePoolId": remote_pool_id, "remoteVstoreId": 0,
                "remoteNameRule": remote_name_rule, "enableCompress": False, "syncPair": True,
                "syncSnapPolicy": 0, "createType": 0, "reservedConsistencySnapSwitch": 0
            },
            "objs": [{"id": local_fs_id, "vstoreId": 0}]
        }
        if remote_name_rule == 2:
            data["replication"]["namePrefix"] = RepFileSystemNameRule.NamePrefix
            data["replication"]["nameSuffix"] = name_suffix
        url = Constant.CREATE_REMOTE_REPLICATION_FILESYSTEM_PAIR
        res = self.rest_client.normal_request(url, data=data, method="post")
        err_msg = "Failed to create remote replication filesystem pair"
        rsp_data = StorageInf.omstask_result_parse(err_msg, res)
        LOG.info("Success to create remote replication filesystem[%s] pair.", local_fs_id)
        return rsp_data

    @retry(retry_times=3, wait_times=20, log=LOG, task="split_remote_replication_filesystem_pair")
    def split_remote_replication_filesystem_pair(self, pair_id):
        LOG.info("Start to split remote replication filesystem pair[%s].", pair_id)
        data = {"ID": pair_id}
        url = Constant.SPLIT_REMOTE_REPLICATION_FILESYSTEM_PAIR.format(deviceId=self.device_id)
        res = self.rest_client.normal_request(url, data=data, method="put")
        err_msg = "Failed to split remote replication filesystem pair"
        rsp_data = StorageInf.result_parse(err_msg, res)
        LOG.info("Success to split remote replication filesystem pair")
        return rsp_data

    @retry(retry_times=3, wait_times=20, log=LOG, task="remote_replication_filesystem_pair_cancel_secondary_write_lock")
    def remote_replication_filesystem_pair_cancel_secondary_write_lock(self, pair_id):
        LOG.info("Start to cancel secondary write lock.")
        data = {"ID": pair_id}
        url = Constant.CANCEL_SECONDARY_WRITE_LOCK.format(deviceId=self.device_id)
        res = self.rest_client.normal_request(url, data=data, method="put")
        err_msg = "Failed to to cancel secondary write lock"
        rsp_data = StorageInf.result_parse(err_msg, res)
        LOG.info("Success to cancel secondary write lock.")
        return rsp_data

    @retry(retry_times=3, wait_times=20, log=LOG, task="remote_replication_filesystem_pair_set_secondary_write_lock")
    def remote_replication_filesystem_pair_set_secondary_write_lock(self, pair_id):
        LOG.info("Start to set secondary write lock.")
        data = {"ID": pair_id}
        url = Constant.SET_SECONDARY_WRITE_LOCK.format(deviceId=self.device_id)
        res = self.rest_client.normal_request(url, data=data, method="put")
        err_msg = "Failed to set secondary write lock."
        rsp_data = StorageInf.result_parse(err_msg, res)
        LOG.info("Success to set secondary write lock.")
        return rsp_data

    @retry(retry_times=3, wait_times=20, log=LOG, task="sync_remote_replication_filesystem_pair")
    def sync_remote_replication_filesystem_pair(self, pair_id, vstore_id, is_full_copy):
        LOG.info("Start to sync remote replication filesystem pair.")
        data = {"ID": pair_id, "vstoreId": vstore_id, "isFullCopy": is_full_copy}
        url = Constant.SYNC_REMOTE_REPLICATION_FILESYSTEM_PAIR.format(deviceId=self.device_id)
        res = self.rest_client.normal_request(url, data=data, method="put")
        err_msg = "Failed to sync remote replication filesystem pair"
        rsp_data = StorageInf.result_parse(err_msg, res)
        LOG.info("Success to sync remote replication filesystem pair.")
        return rsp_data

    def delete_remote_replication_filesystem_pair(self, pair_id, is_local_del=False):
        LOG.info("Start to delete remote replication filesystem pair[%s].", pair_id)
        data = {"ISLOCALDELETE": is_local_del, "TOSYNCSRWHENDELETE": False}
        url = Constant.REMOTE_REPLICATION_FILESYSTEM_PAIR_OPT.format(deviceId=self.device_id, id=pair_id)
        res = self.rest_client.normal_request(url, data=data, method="delete")
        err_msg = "Start to delete remote replication filesystem pair[%s]" % pair_id
        rsp_data = StorageInf.result_parse(err_msg, res)
        LOG.info("Success to delete remote replication filesystem pair[%s].", pair_id)
        return rsp_data

    def delete_hyper_metro_filesystem_pair(self, pair_id, vstore_id, is_local_del=False):
        LOG.info("Start to delete hyper metro filesystem pair")
        url = Constant.DELETE_HYPER_METRO_PAIR.format(deviceId=self.device_id, id=pair_id)
        data = {"ISLOCALDELETE": is_local_del, "vstoreId": vstore_id}
        res = self.rest_client.normal_request(url, data=data, method="delete")
        err_mgs = "Failed to to delete hyper metro filesystem pair"
        rsp_data = StorageInf.result_parse(err_mgs, res)
        LOG.info("Success to delete hyper metro filesystem pair")
        return rsp_data

    @retry(retry_times=3, wait_times=20, log=LOG, task="delete_hyper_metro_vstore_pair")
    def delete_hyper_metro_vstore_pair(self, pair_id, is_local_del=False):
        LOG.info("Start to delete hyper metro vstore pair")
        url = Constant.DELETE_HYPER_METRO_VSTORE_PAIR.format(deviceId=self.device_id, id=pair_id)
        data = {"isLocalDelete": is_local_del}
        res = self.rest_client.normal_request(url, data=data, method="delete")
        err_msg = "Failed to delete hyper metro vstore pair"
        rsp_data = StorageInf.result_parse(err_msg, res)
        LOG.info("Success to delete hyper metro vstore pair.")
        return rsp_data

    def split_filesystem_hyper_metro_domain(self, domain_id):
        LOG.info("Start to split filesystem hyper metro domain, domain_id[%s]", domain_id)
        data = {"ID": domain_id}
        url = Constant.SPLIT_FILESYSTEM_HYPER_METRO_DOMAIN.format(deviceId=self.device_id)
        res = self.rest_client.normal_request(url, data=data, method="post")
        err_msg = "Failed to split filesystem hyper metro domain, domain_id[%s]" % domain_id
        rsp_data = StorageInf.result_parse(err_msg, res)
        LOG.info("Success to split filesystem hyper metro domain, domain_id[%s]", domain_id)
        return rsp_data

    def delete_filesystem_hyper_metro_domain(self, domain_id, is_local_del=False):
        LOG.info("Start to delete filesystem hyper metro domain, domain_id[%s], is_local_del[%s].", domain_id, is_local_del)
        data = {"ISLOCALDELETE": is_local_del}
        url = Constant.DELETE_FILESYSTEM_HYPER_METRO_DOMAIN.format(deviceId=self.device_id, id=domain_id)
        res = self.rest_client.normal_request(url, data=data, method="delete")
        err_msg = "Failed to delete filesystem hyper metro domain, domain_id[%s], is_local_del[%s]." % (domain_id, is_local_del)
        rsp_data = StorageInf.result_parse(err_msg, res)
        LOG.info("Success to delete filesystem hyper metro domain, domain_id[%s], is_local_del[%s].", domain_id, is_local_del)
        return rsp_data

    def swap_role_replication_pair(self, pair_id, vstore_id=0):
        LOG.info("Swap replication pair[%s] role start", pair_id)
        data = {"ID": pair_id, "vstoreId": vstore_id}
        url = Constant.SWAP_ROLE_REPLICATION_PAIR.format(deviceId=self.device_id)
        res = self.rest_client.normal_request(url, data=data, method="put")
        err_msg = "Swap replication pair[%s] role failed" % pair_id
        StorageInf.result_parse(err_msg, res)
        LOG.info("Swap replication pair[%s] role success", pair_id)

    def swap_role_fs_hyper_metro_domain(self, domain_id):
        LOG.info("Swap role fs hyper metro domain[%s] start.", domain_id)
        data = {"ID": domain_id}
        url = Constant.SWAP_ROLE_FS_HYPER_METRO_DOMAIN.format(deviceId=self.device_id)
        res = self.rest_client.normal_request(url, data=data, method="post")
        err_msg = "Swap role fs hyper metro domain[%s] failed" % domain_id
        StorageInf.result_parse(err_msg, res)
        LOG.info("Swap role fs hyper metro domain[%s] success.", domain_id)

    def change_fs_hyper_metro_domain_second_access(self, domain_id, access):
        LOG.info("Change fs hyper metro domain[%s] second access[%s] start.", domain_id, access)
        data = {"ID": domain_id, "access": access}
        url = Constant.CHANGE_FS_HYPER_METRO_DOMAIN_SECOND_ACCESS.format(deviceId=self.device_id)
        res = self.rest_client.normal_request(url, data=data, method="post")
        err_msg = "Change fs hyper metro domain[%s] second access[%s] failed." % (domain_id, access)
        StorageInf.result_parse(err_msg, res)
        LOG.info("Change fs hyper metro domain[%s] second access[%s] success.", domain_id, access)

    def join_fs_hyper_metro_domain(self, domain_id):
        LOG.info("Join fs hyper metro domain[%s] start", domain_id)
        data = {"ID": domain_id}
        url = Constant.JOIN_FS_HYPER_METRO_DOMAIN.format(deviceId=self.device_id)
        res = self.rest_client.normal_request(url, data=data, method="post")
        err_msg = "Failed to join fs hyper metro domain[%s]" % domain_id
        StorageInf.result_parse(err_msg, res)
        LOG.info("Join fs hyper metro domain[%s] success", domain_id)
