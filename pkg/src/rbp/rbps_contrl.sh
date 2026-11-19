#!/bin/sh
# Copyright (c) 2026 Huawei Technologies Co., Ltd.
# oGRAC is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

set -u

usage()
{
    echo "Usage: $0 {-start|-stop|-stop_force|-check} node_id"
}

cms_success()
{
    echo "RES_SUCCESS"
    exit 0
}

cms_failed()
{
    echo "RES_FAILED"
    exit 1
}

find_rbps_ctl()
{
    script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd)
    if [ -x "${script_dir}/rbps_ctl" ]; then
        printf '%s' "${script_dir}/rbps_ctl"
        return 0
    fi
    command -v rbps_ctl 2>/dev/null || true
}

ACTION="${1:-}"
NODE_ID="${2:-}"
[ -n "$ACTION" ] && [ -n "$NODE_ID" ] || { usage; cms_failed; }

CTL=$(find_rbps_ctl)
[ -n "$CTL" ] || cms_failed

case "$ACTION" in
    -start)
        "$CTL" start >/dev/null 2>&1 && cms_success
        cms_failed
        ;;
    -stop)
        "$CTL" stop >/dev/null 2>&1 && cms_success
        cms_failed
        ;;
    -stop_force)
        "$CTL" stop_force >/dev/null 2>&1 && cms_success
        cms_failed
        ;;
    -check)
        status_out=$("$CTL" status 2>/dev/null || true)
        printf '%s\n' "$status_out" | grep -q '^rbps is running:' && cms_success
        cms_failed
        ;;
    *)
        usage
        cms_failed
        ;;
esac
