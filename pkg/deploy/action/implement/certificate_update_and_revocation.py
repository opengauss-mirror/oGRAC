#!/usr/bin/env python3
"""Certificate update and revocation management."""

import json
import os
import stat
import sys
import shutil
import getpass
import grp
import pwd
from datetime import datetime, timedelta, timezone

from dateutil import parser

CUR_PATH = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CUR_PATH, "../"))
from logic.common_func import exec_popen
from om_log import LOGGER as LOG

from config import cfg as _cfg, load_env_defaults
_paths = _cfg.paths


class CertificateUpdateAndRevocation(object):
    def __init__(self):
        env = load_env_defaults()
        certificate_path = _paths.certificates_dir
        self.ca_file_path = _paths.ca_crt
        self.cert_file_path = _paths.mes_crt
        self.key_file_path = _paths.mes_key
        self.crl_file_path = _paths.mes_crl
        self.ograc_user = env.get("ograc_user", "ograc")
        self.ograc_group = env.get("ograc_group", "ograc")
        self.ograc_uid = pwd.getpwnam(self.ograc_user).pw_uid
        self.ograc_gid = grp.getgrnam(self.ograc_group).gr_gid
        if not os.path.exists(certificate_path):
            os.makedirs(certificate_path)
            os.chmod(certificate_path, 0o700)
            os.chown(certificate_path, self.ograc_uid, self.ograc_gid)

    @staticmethod
    def check_key_passwd(key_file_path, passwd):
        cmd = f"openssl rsa -in '{key_file_path}' -check -noout -passin pass:'{passwd}'"
        ret_code, _, stderr = exec_popen(cmd)
        stderr = str(stderr)
        stderr.replace(passwd, "****")
        if ret_code:
            raise Exception("The password is incorrect.")

    @staticmethod
    def get_crt_modulus(cert_file_path):
        cmd = f"openssl x509 -noout -modulus -in '{cert_file_path}' | openssl md5"
        ret_code, stdout, stderr = exec_popen(cmd)
        if ret_code:
            raise Exception("Failed to get crt modulus, output:%s" % str(stderr))
        return str(stdout)

    @staticmethod
    def get_key_modulus(key_file_path, passwd):
        cmd = f"echo -e '{passwd}' | openssl rsa -noout -modulus -in '{key_file_path}' | openssl md5"
        ret_code, stdout, stderr = exec_popen(cmd)
        stderr = str(stderr)
        stderr.replace(passwd, "****")
        if ret_code:
            raise Exception("Failed to get key modulus, output:%s" % str(stderr))
        return str(stdout)

    @staticmethod
    def verify_ca_cert_chain(ca_file_path, cert_file_path):
        cmd = f"openssl verify -CAfile '{ca_file_path}' '{cert_file_path}'"
        ret_code, _, stderr = exec_popen(cmd)
        if ret_code:
            raise Exception("The root certificate does not match the certificate chain")

    @staticmethod
    def get_crt_serial_num(cert_file_path):
        cmd = f"openssl x509 -in '{cert_file_path}' -noout -serial"
        ret_code, stdout, stderr = exec_popen(cmd)
        if ret_code:
            raise Exception("Failed to get crt serial number, output:%s" % str(stderr))
        return str(stdout)

    @staticmethod
    def get_revoked_cert_by_serial_num(crl_file_path, crt_serial_num):
        cmd = f"openssl crl -in '{crl_file_path}' -noout -text | grep -A 1 'Revoked Certificates' | grep 'Serial Number: {crt_serial_num}'"
        ret_code, stdout, stderr = exec_popen(cmd)
        if ret_code:
            return 0
        return 1

    @staticmethod
    def update_certificate_passwd(passwd):
        dbstor_lib = _paths.dbstor_lib
        update_script = _paths.update_ograc_passwd_py
        cmd = f'su -s /bin/bash - {_cfg.user} -c "'
        cmd += f"tmp_path=${{LD_LIBRARY_PATH}};export LD_LIBRARY_PATH={dbstor_lib}:${{LD_LIBRARY_PATH}};"
        cmd += f"echo -e '{passwd}' | python3 -B {update_script} update_mes_key_pwd;"
        cmd += 'export LD_LIBRARY_PATH=${tmp_path}"'
        ret_code, _, stderr = exec_popen(cmd)
        stderr = str(stderr)
        stderr.replace(passwd, "****")
        if ret_code:
            raise Exception("update certificate passwd failed, output:%s" % str(stderr))

    def update_crt_key(self, cert_file_path, key_file_path):
        passwd = getpass.getpass("Enter the certificate and password:")
        if len(passwd) > 32:
            raise Exception("cert pwd is too long. The length should not exceed 32.")
        self.check_key_passwd(key_file_path, passwd)
        certificate_modulus = self.get_crt_modulus(cert_file_path)
        private_key_modulus = self.get_key_modulus(key_file_path, passwd)
        if certificate_modulus == private_key_modulus:
            LOG.info("The certificate matches the private key.")
        else:
            raise Exception("The certificate and private key do not match.")
        self.verify_ca_cert_chain(self.ca_file_path, cert_file_path)
        if os.path.exists(self.crl_file_path):
            crt_serial_num = self.get_crt_serial_num(cert_file_path)
            if self.get_revoked_cert_by_serial_num(self.crl_file_path, crt_serial_num):
                raise Exception("The certificate has been revoked.")
            else:
                LOG.info("The certificate is valid.")
        shutil.copy(cert_file_path, self.cert_file_path)
        shutil.copy(key_file_path, self.key_file_path)
        os.chown(self.cert_file_path, self.ograc_uid, self.ograc_gid)
        os.chown(self.key_file_path, self.ograc_uid, self.ograc_gid)
        self.update_certificate_passwd(passwd)
        print("update crt and key succeed.")

    def update_ca_crt_key(self, ca_file_path, cert_file_path, key_file_path):
        passwd = getpass.getpass("Enter the certificate and password:")
        if len(passwd) > 32:
            raise Exception("cert pwd is too long. The length should not exceed 32.")
        self.check_key_passwd(key_file_path, passwd)
        certificate_modulus = self.get_crt_modulus(cert_file_path)
        private_key_modulus = self.get_key_modulus(key_file_path, passwd)
        if certificate_modulus == private_key_modulus:
            LOG.info("The certificate matches the private key.")
        else:
            raise Exception("The certificate and private key do not match.")
        self.verify_ca_cert_chain(ca_file_path, cert_file_path)
        shutil.copy(ca_file_path, self.ca_file_path)
        shutil.copy(cert_file_path, self.cert_file_path)
        shutil.copy(key_file_path, self.key_file_path)
        os.chown(self.ca_file_path, self.ograc_uid, self.ograc_gid)
        os.chown(self.cert_file_path, self.ograc_uid, self.ograc_gid)
        os.chown(self.key_file_path, self.ograc_uid, self.ograc_gid)
        self.update_certificate_passwd(passwd)
        print("update ca, crt and key succeed.")

    def query_crt_info(self):
        cmd = f"openssl x509 -in '{self.cert_file_path}' -text -noout"
        ret_code, stdout, stderr = exec_popen(cmd)
        stderr = str(stderr)
        if ret_code:
            raise Exception("query certifcate info failed, output:%s" % str(stderr))
        print(str(stdout))


if __name__ == "__main__":
    cert_update_and_revocation = CertificateUpdateAndRevocation()
    _args = []
    action = sys.argv[1]
    if len(sys.argv) > 2:
        _args = sys.argv[2:]
    try:
        getattr(cert_update_and_revocation, action)
    except AttributeError as err:
        err_msg = "Currently, you can modify the certificate revocation list,"\
                  " update certificates, and query certificate information.\n"\
                  "example:\n"\
                  "query_crt_info\n"\
                  "update_crt_key cert_file_path, key_file_path\n"\
                  "update_ca_crt_key ca_file_path, cert_file_path, key_file_path\n"\
                  "update_certificate_crl crl_file_path"
        exit(err_msg)
    try:
        getattr(cert_update_and_revocation, action)(*_args)
    except Exception as err:
        exit(str(err))
