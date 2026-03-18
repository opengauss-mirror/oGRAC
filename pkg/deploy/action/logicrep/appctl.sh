#!/bin/bash
################################################################################
# logicrep 部署入口（重构版 - 薄壳）
#
# - 仅做：读取配置 + 转发 ACTION 到 Python 编排器
# - 业务逻辑全部在 logicrep_deploy.py / logicrep_ctl.py 中实现
################################################################################

set +x
set -e -u

CURRENT_PATH=$(dirname "$(readlink -f "$0")")
SCRIPT_NAME="logicrep_refactored/$(basename "$0")"

# 读取配置（允许失败回退）
eval "$(python3 "${CURRENT_PATH}/config.py" --shell-env)" || true

LOG_DIR="${LOGICREP_LOG_DIR:-/opt/ograc/log/logicrep}"
LOG_FILE="${LOGICREP_LOG_FILE:-${LOG_DIR}/logicrep_deploy.log}"

mkdir -p "${LOG_DIR}" 2>/dev/null || true
touch "${LOG_FILE}" 2>/dev/null || true

usage() {
  echo "Usage: ${0##*/} {start|startup|shutdown|stop|install|uninstall|pre_upgrade|upgrade_backup|upgrade|rollback|check_status|init_container}. [File:${SCRIPT_NAME}]"
  exit 1
}

if [ $# -lt 1 ]; then
  usage
fi

ACTION=$1
shift

python3 "${CURRENT_PATH}/logicrep_deploy.py" "${ACTION}" "$@" 2>&1 | tee -a "${LOG_FILE}"
exit_code=${PIPESTATUS[0]}
exit ${exit_code}
