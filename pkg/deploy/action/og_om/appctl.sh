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

################################################################################
# og_om 部署入口（重构版 - 薄壳）
#
# - 仅做：读取配置 + 转发 ACTION 到 Python 编排器
# - 业务逻辑全部在 og_om_deploy.py / og_om_ctl.py 中实现
################################################################################

set +x
set -e -u

CURRENT_PATH=$(dirname "$(readlink -f "$0")")
SCRIPT_NAME="og_om_refactored/$(basename "$0")"
DEFAULT_OGRAC_HOME=$(cd "${CURRENT_PATH}/../.." && pwd)

# 读取配置（允许失败回退）
eval "$(python3 "${CURRENT_PATH}/config.py" --shell-env)" || true

LOG_DIR="${OGOM_LOG_DIR:-${DEFAULT_OGRAC_HOME}/log/og_om}"
LOG_FILE="${OGOM_LOG_FILE:-${LOG_DIR}/om_deploy.log}"

mkdir -p "${LOG_DIR}" 2>/dev/null || true
touch "${LOG_FILE}" 2>/dev/null || true

usage() {
  echo "Usage: ${0##*/} {start|stop|install|uninstall|pre_install|pre_upgrade|check_status|upgrade|rollback|post_upgrade|backup|restore|upgrade_backup}. [File:${SCRIPT_NAME}]"
  exit 1
}

if [ $# -lt 1 ]; then
  usage
fi

ACTION=$1
shift

python3 "${CURRENT_PATH}/og_om_deploy.py" "${ACTION}" "$@" 2>&1 | tee -a "${LOG_FILE}"
exit_code=${PIPESTATUS[0]}

if [ ${exit_code} -ne 0 ]; then
  echo "og_om ${ACTION} failed (exit code: ${exit_code}). Diagnostics emitted above. [Line:${LINENO}, File:${SCRIPT_NAME}]"
fi
exit ${exit_code}
