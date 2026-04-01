#!/bin/bash
################################################################################
# oGRAC 薄壳入口（重构版）
# 所有业务逻辑已迁移至 Python 编排器，此脚本仅负责：
#   1. 加载配置（通过 config.py --shell-env）
#   2. 文件锁防重入
#   3. 将 action 分发给 ograc_deploy.py / ograc_upgrade.py
#   4. dr_operate 保留交互式密码输入（Python 无法安全处理 read -s）
################################################################################
set +x
CURRENT_PATH=$(dirname "$(readlink -f "$0")")
LOCK_DIR="/tmp/ograc_deploy_lock"

eval "$(python3 "${CURRENT_PATH}/config.py" --shell-env 2>/dev/null)"
OGRAC_HOME="${OGRAC_HOME:-/opt/ograc}"
DEPLOY_LOG_DIR="${DEPLOY_LOG_DIR:-${OGRAC_HOME}/log/deploy}"
OM_DEPLOY_LOG_FILE="${OM_DEPLOY_LOG_FILE:-${DEPLOY_LOG_DIR}/deploy.log}"
mkdir -p "${DEPLOY_LOG_DIR}"

log_info()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO ] $*" | tee -a "${OM_DEPLOY_LOG_FILE}"; }
log_error() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" | tee -a "${OM_DEPLOY_LOG_FILE}" >&2; }

acquire_lock() {
    mkdir "${LOCK_DIR}" 2>/dev/null || { log_error "Another deploy is running"; return 1; }
    trap 'rm -rf "${LOCK_DIR}"' EXIT
}

run_deploy() {
    local action="$1"; shift
    log_info "=== ${action} begin ==="
    python3 -B "${CURRENT_PATH}/ograc_deploy.py" "${action}" "$@"
    local ret=$?
    [ ${ret} -eq 0 ] && log_info "=== ${action} success ===" || log_error "=== ${action} failed (ret=${ret}) ==="
    return ${ret}
}

usage() {
    log_info "Usage: ${0##*/} {start|stop|install|uninstall|pre_install|pre_upgrade|check_status|upgrade|backup|restore|upgrade_commit|check_point|rollback|clear_upgrade_backup|certificate|dr_operate|config_opt|init_container}"
    exit 1
}

##################################### main #####################################
ACTION="$1"; shift
[ -z "${ACTION}" ] && usage

STORAGE_DEPLOY="${CURRENT_PATH}/storage_deploy"
deploy_mode=$(python3 -c "
import json, os
f = os.path.join('${CURRENT_PATH}', 'config_params_lun.json')
if not os.path.isfile(f):
    f = os.path.join('${CURRENT_PATH}', 'config_params.json')
if os.path.isfile(f):
    print(json.load(open(f)).get('deploy_mode', ''))
" 2>/dev/null)

if [[ "${deploy_mode}" == "dbstor" ]] || [[ "${deploy_mode}" == "combined" ]]; then
    log_info "deploy_mode=${deploy_mode}, routing to storage_deploy flow"
    exec sh "${STORAGE_DEPLOY}/appctl.sh" "${ACTION}" "$@"
fi

case "${ACTION}" in
    dr_operate)
        export PYTHONPATH="${CURRENT_PATH}:${CURRENT_PATH}/compat"
        python3 -B "${CURRENT_PATH}/docker/dr_deploy.py" "$@"
        exit $?
        ;;
    start|stop|pre_install|install|uninstall|check_status|backup|restore|\
    init_container|pre_upgrade|upgrade|rollback|upgrade_commit|check_point|\
    clear_upgrade_backup|certificate|config_opt)
        acquire_lock || exit 1
        run_deploy "${ACTION}" "$@"
        exit $?
        ;;
    *)
        usage
        ;;
esac
