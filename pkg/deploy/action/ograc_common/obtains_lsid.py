#!/usr/bin/env python3
import json
import os
import hashlib
import sys
import uuid
import random
from pathlib import Path

CUR_PATH = os.path.dirname(os.path.realpath(__file__))
ACTION_DIR = os.path.realpath(os.path.join(CUR_PATH, ".."))
OGRAC_HOME = os.path.realpath(os.path.join(ACTION_DIR, ".."))
CONFIG_CANDIDATES = [
    str(Path(os.path.join(ACTION_DIR, "config_params_lun.json"))),
    str(Path(os.path.join(CUR_PATH, "../config/deploy_param.json"))),
]
DBSTOR_UNIFY_FLAG = os.path.exists("/opt/ograc/log/deploy/.dbstor_unify_flag")


def _load_info():
    for config_file in CONFIG_CANDIDATES:
        if not os.path.exists(config_file):
            continue
        with open(config_file, encoding="utf-8") as f:
            return json.load(f)
    return {}


info = _load_info()


def _instance_hash():
    digest = hashlib.sha256(OGRAC_HOME.encode("utf-8")).hexdigest()
    return int(digest[:8], 16)


def _derive_cluster_id():
    cluster_id = str(info.get("cluster_id", "")).strip()
    if cluster_id not in ("", "0"):
        return cluster_id
    return str((_instance_hash() % 255) + 1)


class LSIDGenerate(object):
    def __init__(self, n_type, c_id, p_id, n_id):
        self.n_type = int(n_type)
        self.process_id = int(p_id)
        self.cluster_id = int(c_id)
        self.node_id = int(n_id)
        self.random_seed = -1
        self.info = {}

    @staticmethod
    def generate_uuid(n_type, c_id, c_random, p_id, n_id):
        _id = str(n_type) + str(c_id) + str(c_random) + str(n_id) + str(p_id)
        return str(uuid.uuid3(uuid.NAMESPACE_DNS, _id))

    @staticmethod
    def generate_random_seed():
        cluster_name = str(info.get("cluster_name", "")).strip()
        seed_material = f"{cluster_name}|{OGRAC_HOME}"
        hash_object = int(hashlib.sha256(seed_material.encode('utf-8')).hexdigest(), 16)
        random.seed(hash_object)
        return random.randint(0, 255)

    def generate_lsid(self):
        return int(str(bin(self.n_type))[2:].rjust(2, "0")
                   + str(bin(3))[2:].rjust(2, "0")
                   + str(bin(self.cluster_id))[2:].rjust(8, "0")
                   + str(bin(self.random_seed))[2:].rjust(8, "0")
                   + str(bin(self.process_id))[2:].rjust(4, "0")
                   + str(bin(self.node_id))[2:].rjust(8, "0"), 2)

    def execute(self):
        self.random_seed = self.generate_random_seed()
        process_uuid = self.generate_uuid(self.n_type, self.cluster_id, self.random_seed, self.process_id, self.node_id)
        ls_id = self.generate_lsid()
        return ls_id, process_uuid


if __name__ == "__main__":
    node_type = sys.argv[1]
    cluster_id = _derive_cluster_id()
    process_id = sys.argv[3]
    node_id = sys.argv[4]
    id_generate = LSIDGenerate(node_type, cluster_id, process_id, node_id)
    print("%s\n%s" % id_generate.execute())
