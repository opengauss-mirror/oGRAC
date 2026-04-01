#!/usr/bin/env python3
"""KMC password encryption adapter."""

import os
import sys

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, CURRENT_PATH)

from kmc_adapter import CApiWrapper
from config import cfg as _cfg
_paths = _cfg.paths

PRIMARY_KEYSTORE = _paths.primary_keystore
STANDBY_KEYSTORE = _paths.standby_keystore


class KmcResolve(object):
    @staticmethod
    def kmc_resolve_password(mode, plain_text):
        ret_pwd = ""
        kmc_adapter = CApiWrapper(PRIMARY_KEYSTORE, STANDBY_KEYSTORE)
        kmc_adapter.initialize()
        try:
            if mode == "encrypted":
                ret_pwd = kmc_adapter.encrypt(plain_text)
            if mode == "decrypted":
                ret_pwd = kmc_adapter.decrypt(plain_text)
        except Exception as error:
            raise Exception("Failed to %s password of user [sys]. Error: %s" % (mode, str(error))) from error
        finally:
            kmc_adapter.finalize()
        split_env = os.environ.get('LD_LIBRARY_PATH', '').split(":")
        filtered_env = [e for e in split_env if _paths.dbstor_lib not in e]
        os.environ['LD_LIBRARY_PATH'] = ":".join(filtered_env)
        return ret_pwd

    def encrypted(self, pwd):
        ret_pwd = self.kmc_resolve_password("encrypted", pwd)
        print(ret_pwd)


if __name__ == "__main__":
    kmc_resolve = KmcResolve()
    action = sys.argv[1]
    getattr(kmc_resolve, action)(input().strip())
