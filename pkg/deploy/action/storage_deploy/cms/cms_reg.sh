#!/bin/bash
set +x

source ~/.bashrc > /dev/null 2>&1
CURRENT_PATH=$(dirname $(readlink -f $0))
CMS_ENABLE_FLAG=/opt/ograc/cms/cfg/cms_enable
DAEMONN_LOG_FILE=/opt/ograc/log/deploy/deploy_daemon.log
# 返回结果前等待1s
LOOP_TIME=1

ACTION=$1

function log() {
  printf "[%s] %s\n" "`date -d today \"+%Y-%m-%d %H:%M:%S\"`" "$1" >> ${DAEMONN_LOG_FILE}
}

function check_and_clean_residual_dss() {
    if pgrep -f "cms server -start" > /dev/null; then
        return
    fi
    if ! pgrep -x "dssserver" > /dev/null; then
        return
    fi
    # 清理残留的dssserver进程
    log "[cms reg] stop residual dssserver processes. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    dsscmd stopdss
    sleep 3
    if pgrep -x "dssserver" > /dev/null; then
        dss_pids=$(pgrep -x "dssserver")
        log "[cms reg] Stop dssserver failed, killing residual dssserver processes by force: ${dss_pids}."
        kill -9 $dss_pids
    fi
    log "[cms reg] dssserver processes cleaned up finished. [Line:${LINENO}, File:${SCRIPT_NAME}]"
}

case "$ACTION" in
    enable)
        log "[cms reg] begin to set cms daemon enable. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        if [ ! -f ${CMS_ENABLE_FLAG} ]; then
            check_and_clean_residual_dss
            touch ${CMS_ENABLE_FLAG}
            if [ $? -eq 0 ];then
                chmod 400 ${CMS_ENABLE_FLAG}
                sleep ${LOOP_TIME}
                echo "RES_SUCCESS"
                exit 0
            else
                log "Error: [cms reg] set cms daemon enable failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
                exit 1
            fi
        fi
        sleep ${LOOP_TIME}
        echo "RES_SUCCESS"
        exit 0
        ;;
    disable)
        log "[cms reg] begin to set cms daemon disable. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        if [ -f ${CMS_ENABLE_FLAG} ]; then
            rm -f ${CMS_ENABLE_FLAG}
            if [ $? -eq 0 ];then
                sleep ${LOOP_TIME}
                echo "RES_SUCCESS"
                exit 0
            else
                log "Error: [cms reg] set cms daemon disable failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
                exit 1
            fi
        fi
        sleep ${LOOP_TIME}
        echo "RES_SUCCESS"
        exit 0
        ;;
    *)
        echo "action not support"
        ;;
esac