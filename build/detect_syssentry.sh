#!/bin/bash
# Copyright (c) 2026 Huawei Technologies Co., Ltd.
# oGRAC is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
#
# SysSentry / libxalarm compile defaults (shared by build/common.sh, CMake, Bazel).
# openEuler aarch64 24.03 SP3 -> xalarm ON, legacy ABI
# openEuler aarch64 24.03 SP4 -> xalarm ON, report-event len ABI
# others -> OFF
#
# Sourced: sets ENABLE_XALARMD and ENABLE_XALARM_REPORT_EVENT_LEN to ON/OFF.
# Executed: prints the same variables as KEY=VALUE lines.

OPENEULER_VERSION_PATH="${OPENEULER_VERSION_PATH:-/etc/openEuler-release}"

ENABLE_XALARMD="OFF"
ENABLE_XALARM_REPORT_EVENT_LEN="OFF"

if [[ "$(uname -m)" == "aarch64" ]] && [[ -f "${OPENEULER_VERSION_PATH}" ]]; then
    _oe_rel=$(cat "${OPENEULER_VERSION_PATH}" 2>/dev/null || true)
    if echo "${_oe_rel}" | grep -qw '24.03'; then
        if echo "${_oe_rel}" | grep -qE 'LTS-SP4|SP4'; then
            ENABLE_XALARMD="ON"
            ENABLE_XALARM_REPORT_EVENT_LEN="ON"
        elif echo "${_oe_rel}" | grep -qE 'LTS-SP3|SP3'; then
            ENABLE_XALARMD="ON"
            ENABLE_XALARM_REPORT_EVENT_LEN="OFF"
        fi
    fi
    unset _oe_rel
fi

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "ENABLE_XALARMD=${ENABLE_XALARMD}"
    echo "ENABLE_XALARM_REPORT_EVENT_LEN=${ENABLE_XALARM_REPORT_EVENT_LEN}"
fi
