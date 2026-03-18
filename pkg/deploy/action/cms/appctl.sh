#!/bin/bash
################################################################################
# CMS 部署入口（重构版）
#
# 【重构说明】
# 原 appctl.sh 约 800 行 shell 代码，现精简为薄壳入口：
#   1. 路径解耦: 所有路径通过 cms_config.json 配置，不再硬编码 /opt/ograc
#   2. 代码归一: 重复逻辑已移入 Python 模块（utils.py）
#   3. Python 化: 核心逻辑全部在 cms_deploy.py 中，本脚本仅做调度
#
# 【调用方式】
#   sh appctl.sh <action> [args...]
#
# 【支持的 action】
#   start, stop, pre_install, install, uninstall, check_status,
#   backup, restore, init_container, pre_upgrade, upgrade_backup,
#   upgrade, rollback, post_upgrade
#
# 【返回值】
#   0: 成功
#   1: 失败
################################################################################

set +x
set -e -u

# ---- 定位脚本目录 ----
CURRENT_PATH=$(dirname "$(readlink -f "$0")")
SCRIPT_NAME="cms/$(basename "$0")"

# ---- 读取配置路径（调用 config.py 统一管理，不内嵌 Python）----
eval "$(python3 "${CURRENT_PATH}/config.py" --shell-env)" || {
    OGRAC_HOME="${OGRAC_HOME:-/opt/ograc}"
    CMS_LOG_DIR="${OGRAC_HOME}/log/cms"
}

LOG_FILE="${CMS_LOG_DIR}/cms_deploy.log"

# ---- 确保日志目录存在 ----
mkdir -p "${CMS_LOG_DIR}" 2>/dev/null || true
if [ ! -f "${LOG_FILE}" ]; then
    touch "${LOG_FILE}" 2>/dev/null || true
    chmod 640 "${LOG_FILE}" 2>/dev/null || true
fi

# ---- 用法提示 ----
usage() {
    echo "Usage: ${0##*/} {start|stop|install|uninstall|pre_install|" \
         "pre_upgrade|check_status|upgrade|post_upgrade|rollback|" \
         "upgrade_backup|init_container|backup|restore}" \
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
# 所有核心逻辑（cgroup 管理、iptables、升级/回滚编排、备份校验等）
# 已全部移入 cms_deploy.py，此处仅做转发
python3 "${CURRENT_PATH}/cms_deploy.py" "${ACTION}" "$@" 2>&1 | tee -a "${LOG_FILE}"
exit_code=${PIPESTATUS[0]}

if [ ${exit_code} -ne 0 ]; then
    echo "CMS ${ACTION} failed (exit code: ${exit_code}). [Line:${LINENO}, File:${SCRIPT_NAME}]"
fi

exit ${exit_code}
