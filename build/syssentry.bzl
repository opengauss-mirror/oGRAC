# Copyright (c) 2026 Huawei Technologies Co., Ltd.
# oGRAC is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

# SysSentry (libxalarm) Bazel flags. Enable via build/gen_syssentry_bazelrc.sh or:
#   bazel build --define ENABLE_XALARMD=legacy ...
#   bazel build --define ENABLE_XALARMD=sp4 ...

def syssentry_local_defines():
    return select({
        "//build:syssentry_legacy": [
            "ENABLE_XALARMD",
            "CM_XALARM_LEGACY_REGISTER_ABI",
        ],
        "//build:syssentry_sp4": [
            "ENABLE_XALARMD",
            "CM_XALARM_REPORT_EVENT_HAS_LEN",
        ],
        "//conditions:default": [],
    })

def syssentry_linkopts():
    return select({
        "//build:syssentry_legacy": ["-lxalarm"],
        "//build:syssentry_sp4": ["-lxalarm"],
        "//conditions:default": [],
    })
