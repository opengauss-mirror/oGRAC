#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
KMC password encrypt/decrypt adapter (path-decoupled).

Migrated from action_old/dbstor/kmc_adapter.py to action/ograc_common/.
Eliminates hardcoded /opt/ograc; resolves via OGRAC_HOME env or file location.

All ctypes struct definitions must match WsecAlgId enum in kmc include/wsecv2_type.h.
"""

import os
import stat
import logging

import ctypes
import json
import base64
from ctypes import CFUNCTYPE, c_char, c_int, c_void_p, pointer, c_char_p, Structure, POINTER
from enum import Enum

_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
_OGRAC_HOME = os.environ.get("OGRAC_HOME") or os.path.abspath(os.path.join(_MODULE_DIR, "..", ".."))

SEC_PATH_MAX = 4096
MAX_MK_COUNT = 4096
USE_DBSTOR = ["combined", "dbstor"]

JS_CONF_FILE = os.path.join(_OGRAC_HOME, "config", "deploy_param.json")


class KeCallBackParam(Structure):
    _fields_ = [
        ("notifyCbCtx", c_void_p),
        ("loggerCtx", c_void_p),
        ("hwCtx", c_void_p)]


class KmcHardWareParm(Structure):
    _fields_ = [
        ("len", c_int),
        ("hardParam", c_char_p)]


class KmcConfig(Structure):
    _fields_ = [
        ("primaryKeyStoreFile", c_char * SEC_PATH_MAX),
        ("standbyKeyStoreFile", c_char * SEC_PATH_MAX),
        ("domainCount", c_int),
        ("role", c_int),
        ("procLockPerm", c_int),
        ("sdpAlgId", c_int),
        ("hmacAlgId", c_int),
        ("semKey", c_int),
        ("innerSymmAlgId", c_int),
        ("innerHashAlgId", c_int),
        ("innerHmacAlgId", c_int),
        ("innerKdfAlgId", c_int),
        ("workKeyIter", c_int),
        ("rootKeyIter", c_int)]

    def __init__(self, *args, **kw):
        super(KmcConfig, self).__init__(*args, **kw)
        self.primaryKeyStoreFile = bytes()
        self.standbyKeyStoreFile = bytes()
        self.domainCount = 0
        self.role = 0
        self.sdpAlgId = 0
        self.hmacAlgId = 0
        self.semKey = 0
        self.procLockPerm = 0

        self.innerSymmAlgId = 0
        self.innerHashAlgId = 0
        self.innerHmacAlgId = 0
        self.innerKdfAlgId = 0
        self.workKeyIter = 0
        self.rootKeyIter = 0


class KmcConfigEx(Structure):
    _fields_ = [
        ("enableHw", c_int),
        ("kmcHardWareParm", KmcHardWareParm),
        ("keCbParam", POINTER(KeCallBackParam)),
        ("kmcConfig", KmcConfig),
        ("useDefaultHwCB", c_int)]


class HmacAlgorithm(Enum):
    UNKNOWN_ALGORITHM = 0
    HMAC_SHA256 = 2052
    HMAC_SHA384 = 2053
    HMAC_SHA512 = 2054
    HMAC_SM3 = 2055


class SdpAlgorithm(Enum):
    UNKNOWN_ALGORITHM = 0
    AES128_CBC = 5
    AES256_CBC = 7
    AES128_GCM = 8
    AES256_GCM = 9
    SM4_CBC = 10
    SM4_CTR = 11


class HashAlgorithm(Enum):
    UNKNOWN_ALGORITHM = 0
    HASH_SHA256 = 1028
    HASH_SM3 = 1031


class KdfAlgorithm(Enum):
    PBKDF2_HMAC_SHA256 = 3076
    PBKDF2_HMAC_SM3 = 3079


class KmcConstant:
    SUCCESS = 0


class KmcRole(Enum):
    ROLE_AGENT = 0
    ROLE_MASTER = 1


@CFUNCTYPE(None, c_void_p, c_int, c_char_p)
def kmc_log(ctx, level, _msg):
    msg = str(_msg, encoding='utf-8')
    if level == KmcLogLevel.LOG_ERROR.value:
        logging.error(msg)
    elif level == KmcLogLevel.LOG_WARN.value:
        logging.warning(msg)
    elif level == KmcLogLevel.LOG_INFO.value:
        logging.info(msg)
    elif level == KmcLogLevel.LOG_DEBUG.value or level == KmcLogLevel.LOG_TRACE.value:
        logging.debug(msg)


class KmcLogLevel(Enum):
    LOG_DISABLE = 0
    LOG_ERROR = 1
    LOG_WARN = 2
    LOG_INFO = 3
    LOG_DEBUG = 4
    LOG_TRACE = 5


class KmcInitConf(object):
    def __init__(self, _primary_ks, _standby_ks, _hw_param=None,
                 _enable_hw=False,
                 _use_default_hw_cb=0,
                 _domain_count=2,
                 _role=KmcRole.ROLE_MASTER,
                 _sdp_alg=SdpAlgorithm.AES256_GCM,
                 _hmac_alg=HmacAlgorithm.HMAC_SHA256,
                 _kdf_alg=KdfAlgorithm.PBKDF2_HMAC_SHA256,
                 _hash_alg=HashAlgorithm.HASH_SHA256, **kwargs):
        self.primary_ks = _primary_ks
        self.standby_ks = _standby_ks
        self.hw_param = _hw_param
        self.use_default_hw_cb = _use_default_hw_cb
        self.domain_count = _domain_count
        self.role = _role
        self.sdp_alg = _sdp_alg
        self.hmac_alg = _hmac_alg
        self.kdf_alg = _kdf_alg
        self.hash_alg = _hash_alg
        self.enable_hw = _enable_hw
        self.enable_sm = 0

    def transform_to_gm_config(self):
        self.sdp_alg = SdpAlgorithm.SM4_CTR
        self.hmac_alg = HmacAlgorithm.HMAC_SM3
        self.kdf_alg = KdfAlgorithm.PBKDF2_HMAC_SM3
        self.hash_alg = HashAlgorithm.HASH_SM3


class CApiConstant:
    DEFAULT_WORK_KEY_ITER = 1
    DEFAULT_ROOT_KEY_ITER = 10000
    DEFAULT_SEM_KEY = 0x20161227
    DEFAULT_PROC_LOCK_PERM = 0o600
    DEFAULT_DOMAINID = 0
    DEFAULT_ITER = 1


class CApiWrapper(object):
    """Python wrapper for kmc-ext C API.

    Handles Python-to-C type conversion only; no business logic.
    Limitations: no HW encryption init, no log callback, no key-update callback.
    """

    def __init__(self, primary_keystore=None, standby_keystore=None):
        if primary_keystore is None:
            primary_keystore = os.path.join(_OGRAC_HOME, "common", "config", "primary_keystore.ks")
        if standby_keystore is None:
            standby_keystore = os.path.join(_OGRAC_HOME, "common", "config", "standby_keystore.ks")
        self.deploy_mode = None
        self.initialized = False
        self.kmc_ctx = None
        self.primary_keystore = primary_keystore
        self.standby_keystore = standby_keystore
        self.get_dbstor_para()
        if self.deploy_mode in USE_DBSTOR:
            kmc_lib = os.path.join(_OGRAC_HOME, "dbstor", "lib", "libkmcext.so")
            self.kmc_ext = ctypes.cdll.LoadLibrary(kmc_lib)

    def get_dbstor_para(self):
        with os.fdopen(os.open(JS_CONF_FILE, os.O_RDONLY | os.O_EXCL, stat.S_IWUSR | stat.S_IRUSR), "r") as file_obj:
            json_data = json.load(file_obj)
            self.deploy_mode = json_data.get('deploy_mode', "").strip()

    def initialize(self):
        if self.initialized or self.deploy_mode not in USE_DBSTOR:
            return 0

        conf = KmcInitConf(
            self.primary_keystore,
            self.standby_keystore,
            {},
            False,
            0,
        )
        conf.enable_sm = 0

        use_default_hw_cb = conf.use_default_hw_cb
        kmc_hardware_param = KmcHardWareParm(c_int(0), None)
        ke_cb_param = KeCallBackParam(None, None, None)

        kmc_conf = KmcConfig()
        kmc_conf.primaryKeyStoreFile = bytes(conf.primary_ks, encoding="utf-8")
        kmc_conf.standbyKeyStoreFile = bytes(conf.standby_ks, encoding="utf-8")
        kmc_conf.domainCount = c_int(conf.domain_count)
        kmc_conf.role = c_int(conf.role.value)
        kmc_conf.sdpAlgId = c_int(conf.sdp_alg.value)
        kmc_conf.hmacAlgId = c_int(conf.hmac_alg.value)
        kmc_conf.semKey = c_int(CApiConstant.DEFAULT_SEM_KEY)
        kmc_conf.procLockPerm = c_int(CApiConstant.DEFAULT_PROC_LOCK_PERM)

        kmc_conf.innerSymmAlgId = c_int(conf.sdp_alg.value)
        kmc_conf.innerHashAlgId = c_int(conf.hash_alg.value)
        kmc_conf.innerHmacAlgId = c_int(conf.hmac_alg.value)
        kmc_conf.innerKdfAlgId = c_int(conf.kdf_alg.value)
        kmc_conf.workKeyIter = c_int(CApiConstant.DEFAULT_WORK_KEY_ITER)
        kmc_conf.rootKeyIter = c_int(CApiConstant.DEFAULT_ROOT_KEY_ITER)
        cfg = KmcConfigEx(c_int(conf.enable_hw), kmc_hardware_param,
                          pointer(ke_cb_param), kmc_conf, c_int(use_default_hw_cb))
        ctx = c_void_p()

        self.kmc_ext.KeSetLoggerCallbackEx(kmc_log)
        self.kmc_ext.KeSetLoggerLevel(c_int(4))

        # int KeInitializeEx(KmcConfigEx *kmcConfig, void **ctx)
        status = self.kmc_ext.KeInitializeEx(pointer(cfg), pointer(ctx))
        if status == 0:
            self.kmc_ctx = ctx
            self.initialized = True
        return status

    def encrypt_by_kmc(self, plain):
        result = ""
        ctx = self.kmc_ctx
        plain_text = str(plain).encode("utf-8")
        plain_len = len(plain)
        cipher = c_char_p()
        cipher_len = c_int()
        status = self.kmc_ext.KeEncryptByDomainEx(ctx, CApiConstant.DEFAULT_DOMAINID,
                                                  plain_text, plain_len,
                                                  pointer(cipher), pointer(cipher_len))
        if status == 0:
            result = cipher.value.decode('utf-8')
        return result

    def encrypt_by_base64(self, plain):
        encoded = base64.b64encode(plain.encode('utf-8'))
        return encoded.decode('utf-8')

    def encrypt(self, plain):
        if self.deploy_mode in USE_DBSTOR:
            return self.encrypt_by_kmc(plain)
        return self.encrypt_by_base64(plain)

    def decrypt_by_kmc(self, cipher):
        result = ""
        ctx = self.kmc_ctx
        cipher_text = str(cipher).encode("utf-8")
        cipher_len = len(cipher)
        plain = c_char_p()
        plain_len = c_int()
        status = self.kmc_ext.KeDecryptByDomainEx(ctx, CApiConstant.DEFAULT_DOMAINID,
                                                  cipher_text, cipher_len,
                                                  pointer(plain), pointer(plain_len))
        if status == 0:
            result = plain.value.decode('utf-8')
        return result

    def decrypt_by_base64(self, cipher):
        decoded = base64.b64decode(cipher.encode('utf-8'))
        return decoded.decode('utf-8')

    def decrypt(self, cipher):
        if self.deploy_mode in USE_DBSTOR:
            return self.decrypt_by_kmc(cipher)
        return self.decrypt_by_base64(cipher)

    def finalize(self):
        if not self.initialized or self.deploy_mode not in USE_DBSTOR:
            return 0
        return self.kmc_ext.KeFinalizeEx(pointer(self.kmc_ctx))

    def update_mk(self):
        return self.kmc_ext.KeActiveNewKeyEx(self.kmc_ctx, CApiConstant.DEFAULT_DOMAINID)

    def get_mk_count(self):
        return self.kmc_ext.KeGetMkCountEx(self.kmc_ctx)

    def update_root_key(self):
        return self.kmc_ext.KeUpdateRootKeyEx(self.kmc_ctx)


if __name__ == "__main__":
    import sys
    e_pwd = ""
    mode = ""
    primary_ksf = None
    standby_ksf = None
    res = None
    need_update_mk = False
    need_update_rk = False
    if len(sys.argv) == 2:
        e_pwd = sys.argv[1]
        if e_pwd == "update_mk":
            need_update_mk = True
        elif e_pwd == "update_rk":
            need_update_rk = True
        res = CApiWrapper()
    elif len(sys.argv) == 5:
        mode = sys.argv[1]
        primary_ksf = sys.argv[2]
        standby_ksf = sys.argv[3]
        res = CApiWrapper(primary_ksf, standby_ksf)

    res.initialize()
    if need_update_mk:
        ret = res.update_mk()
        mk_count = res.get_mk_count()
        res.finalize()
        if ret == 0:
            print("update master key success\nNow there are %s master keys in ksf" % mk_count)
            exit(0)
        else:
            exit(1)
    if need_update_rk:
        ret = res.update_root_key()
        res.finalize()
        if ret == 0:
            print("update root key success")
            exit(0)
        else:
            exit(1)

    if mode == "encrypted":
        e_pwd = sys.argv[4]
        encrypted_passwd = res.encrypt(e_pwd)
        print(encrypted_passwd)

    res.finalize()
