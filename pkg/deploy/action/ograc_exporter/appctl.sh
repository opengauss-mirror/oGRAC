#!/bin/bash
################################################################################
# ograc_exporter 部署入口（重构版 - 薄壳）
#
# - 仅做：读取配置 + 转发 ACTION 到 Python 编排器
# - 业务逻辑全部在 ograc_exporter_deploy.py / ograc_exporter_ctl.py 中实现
################################################################################

set +x
set -e -u

CURRENT_PATH=$(dirname "$(readlink -f "$0")")
SCRIPT_NAME="ograc_exporter_refactored/$(basename "$0")"
DEFAULT_OGRAC_HOME=$(cd "${CURRENT_PATH}/../.." && pwd)

# 读取配置（允许失败回退）
eval "$(python3 "${CURRENT_PATH}/config.py" --shell-env)" || true

LOG_DIR="${EXPORTER_LOG_DIR:-${DEFAULT_OGRAC_HOME}/log/ograc_exporter}"
LOG_FILE="${EXPORTER_LOG_FILE:-${LOG_DIR}/ograc_exporter.log}"

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

python3 "${CURRENT_PATH}/ograc_exporter_deploy.py" "${ACTION}" "$@" 2>&1 | tee -a "${LOG_FILE}"
exit_code=${PIPESTATUS[0]}
exit ${exit_code}
