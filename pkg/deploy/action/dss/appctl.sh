#!/bin/bash
################################################################################
# DSS 部署入口（重构版）
#
# 【重构说明】
# 原 appctl.sh 约 168 行 shell 代码，现精简为薄壳入口：
#   1. 路径解耦: 所有路径通过 dss_config.json 配置
#   2. Python 化: 核心逻辑全部在 dss_deploy.py 中
#
# 【调用方式】
#   sh appctl.sh <action> [args...]
################################################################################

set +x
set -e -u

CURRENT_PATH=$(dirname "$(readlink -f "$0")")
SCRIPT_NAME="dss/$(basename "$0")"

# ---- 读取配置路径 ----
if ! eval "$(python3 "${CURRENT_PATH}/config.py" --shell-env)"; then
    echo "Failed to resolve DSS environment from config_params_lun.json/module_config." >&2
    exit 1
fi

LOG_FILE="${DSS_LOG_DIR}/dss_deploy.log"

# ---- 确保日志目录存在 ----
mkdir -p "${DSS_LOG_DIR}" 2>/dev/null || true
if [ ! -f "${LOG_FILE}" ]; then
    touch "${LOG_FILE}" 2>/dev/null || true
    chmod 640 "${LOG_FILE}" 2>/dev/null || true
fi

# ---- 用法提示 ----
usage() {
    echo "Usage: ${0##*/} {start|stop|install|uninstall|pre_install|" \
         "pre_upgrade|check_status|upgrade|rollback|upgrade_backup}" \
         "[Line:${LINENO}, File:${SCRIPT_NAME}]"
    exit 1
}

# ---- 参数解析 ----
if [ $# -lt 1 ]; then
    usage
fi

ACTION=$1
shift

# ---- 调度到 Python 部署编排器 ----
python3 "${CURRENT_PATH}/dss_deploy.py" "${ACTION}" "$@" 2>&1 | tee -a "${LOG_FILE}"
exit_code=${PIPESTATUS[0]}

if [ ${exit_code} -ne 0 ]; then
    echo "DSS ${ACTION} failed (exit code: ${exit_code}). [Line:${LINENO}, File:${SCRIPT_NAME}]"
fi

exit ${exit_code}
