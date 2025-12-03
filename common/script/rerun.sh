
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)
source ${CURRENT_PATH}/log4sh.sh
LOCK_NAME="/opt/ograc/common/script/rerun.lock"


ACTION=$1
case "$ACTION" in
    start)
        if ( set -o noclobber; echo "$$" > "$LOCK_NAME") 2> /dev/null;then
            trap 'rm -f "$LOCK_NAME"; exit $?' INT TERM EXIT
            ### 开始正常流程
            logAndEchoInfo "[rerun] begin to start service. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            systemctl daemon-reload

            systemctl start ograc.timer
            if [ $? -eq 0 ]; then
                logAndEchoInfo "[rerun] start ograc.timer success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            else
                logAndEchoError "[rerun] start ograc.timer failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
                exit 1
            fi
            systemctl status ograc.timer


            systemctl enable ograc.timer
            if [ $? -eq 0 ]; then
                logAndEchoInfo "[rerun] enable ograc.timer success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            else
                logAndEchoError "[rerun] enable ograc.timer failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
                exit 1
            fi
            systemctl is-enabled ograc.timer

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
            sh /opt/ograc/action/appctl.sh stop
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