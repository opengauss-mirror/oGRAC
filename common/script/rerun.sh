
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)
OGRAC_HOME=$(readlink -f "${CURRENT_PATH}/../..")
ACTION_DIR="${OGRAC_HOME}/action"
CONFIG_PY="${ACTION_DIR}/config.py"
if [ -f "${CONFIG_PY}" ]; then
    eval "$(python3 "${CONFIG_PY}" --shell-env 2>/dev/null)" || true
fi
source ${CURRENT_PATH}/log4sh.sh
LOCK_NAME="${CURRENT_PATH}/rerun.lock"


ACTION=$1
case "$ACTION" in
    start)
        if ( set -o noclobber; echo "$$" > "$LOCK_NAME") 2> /dev/null;then
            trap 'rm -f "$LOCK_NAME"; exit $?' INT TERM EXIT
            ### 开始正常流程
            logAndEchoInfo "[rerun] begin to start service. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            systemctl daemon-reload

            systemctl start "${OGRAC_DAEMON_TIMER}"
            if [ $? -eq 0 ]; then
                logAndEchoInfo "[rerun] start ${OGRAC_DAEMON_TIMER} success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            else
                logAndEchoError "[rerun] start ${OGRAC_DAEMON_TIMER} failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
                exit 1
            fi
            systemctl status "${OGRAC_DAEMON_TIMER}"


            systemctl enable "${OGRAC_DAEMON_TIMER}"
            if [ $? -eq 0 ]; then
                logAndEchoInfo "[rerun] enable ${OGRAC_DAEMON_TIMER} success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            else
                logAndEchoError "[rerun] enable ${OGRAC_DAEMON_TIMER} failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
                exit 1
            fi
            systemctl is-enabled "${OGRAC_DAEMON_TIMER}"

            ### 正常流程结束

            ### Removing lock
            rm -f $LOCK_NAME
            trap - INT TERM EXIT
        else
            logAndEchoError "Failed to acquire lockfile: $LOCK_NAME. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            logAndEchoError "Held by $(cat $LOCK_NAME). [Line:${LINENO}, File:${SCRIPT_NAME}]"
            logAndEchoError "rerun start failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            exit 1
        fi

        exit $?
        ;;
    stop)
        if ( set -o noclobber; echo "$$" > "$LOCK_NAME") 2> /dev/null;then
            trap 'rm -f "$LOCK_NAME"; exit $?' INT TERM EXIT

            logAndEchoInfo "[rerun] begin to stop service. [Line:${LINENO}, File:${SCRIPT_NAME}]"

            ### 开始正常流程
            sh "${ACTION_DIR}/appctl.sh" stop
            if [ $? -eq 0 ]; then
                logAndEchoInfo "[rerun] stop service success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            else
                logAndEchoError "[rerun] stop service failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
                exit 1
            fi
            ### 正常流程结束

            ### Removing lock
            rm -f $LOCK_NAME
            trap - INT TERM EXIT
        else
            logAndEchoError "Failed to acquire lockfile: $LOCK_NAME. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            logAndEchoError "Held by $(cat $LOCK_NAME). [Line:${LINENO}, File:${SCRIPT_NAME}]"
            logAndEchoError "rerun stop failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            exit 1
        fi


        exit $?
        ;;
    *)
        echo "action not support"
        ;;
esac