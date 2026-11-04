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
