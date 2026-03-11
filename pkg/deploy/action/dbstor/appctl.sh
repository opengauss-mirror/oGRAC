#!/bin/bash
################################################################################
# dbstor 部署入口（重构版 - 薄壳）
#
# - 仅做：读取配置 + 转发 ACTION 到 Python 编排器
# - 业务逻辑全部在 dbstor_deploy.py / dbstor_ctl.py 中实现
################################################################################

set +x
set -e -u

CURRENT_PATH=$(dirname "$(readlink -f "$0")")
SCRIPT_NAME="dbstor_refactored/$(basename "$0")"

# 读取配置
eval "$(python3 "${CURRENT_PATH}/config.py" --shell-env)" || true

LOG_DIR="${DBSTOR_LOG_DIR:-/opt/ograc/log/dbstor}"
LOG_FILE="${DBSTOR_LOG_FILE:-${LOG_DIR}/install.log}"

mkdir -p "${LOG_DIR}" 2>/dev/null || true
touch "${LOG_FILE}" 2>/dev/null || true

usage() {
  echo "Usage: ${0##*/} {start|stop|install|uninstall|pre_install|pre_upgrade|check_status|upgrade|rollback|upgrade_backup|init_container|post_upgrade}. [File:${SCRIPT_NAME}]"
  exit 1
}

if [ $# -lt 1 ]; then
  usage
fi

ACTION=$1
shift

python3 "${CURRENT_PATH}/dbstor_deploy.py" "${ACTION}" "$@" 2>&1 | tee -a "${LOG_FILE}"
exit_code=${PIPESTATUS[0]}
exit ${exit_code}
