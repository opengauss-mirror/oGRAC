#!/bin/bash

online_list=()


logAndEchoInfo "check ograc status."
cms_info=$(ps -ef | grep cms | grep server | grep start | grep -v grep)
if [[ -n ${cms_info} ]]; then
    logAndEchoInfo "cms process info:\n ${cms_info}"
    online_list[${#online_list[*]}]="cms"
fi

pidof ogracd > /dev/null 2>&1
if [ $? -eq 0 ]; then
    ogracd_info=$(ps -ef | grep ogracd | grep /mnt/dbdata/local/ograc/tmp/data | grep -v grep)
    logAndEchoInfo "ogracd process info:\n ${ogracd_info}"
    online_list[${#online_list[*]}]="ogracd"
fi

ogmgr_info=$(ps -ef | grep "python3 /opt/ograc/og_om/service/ogmgr/uds_server.py" | grep -v grep)
if [[ -n ${ogmgr_info} ]]; then
    logAndEchoInfo "ogmgr process info:\n ${ogmgr_info}"
    online_list[${#online_list[*]}]="ogmgr"
fi

ograc_exporter_info=$(ps -ef | grep "python3 /opt/ograc/og_om/service/ograc_exporter/exporter/execute.py" | grep -v grep)
if [[ -n ${ograc_exporter_info} ]]; then
    logAndEchoInfo "ograc_exporter process info:\n ${ograc_exporter_info}"
    online_list[${#online_list[*]}]="ograc_exporter"
fi

daemon_info=$(ps -ef | grep -v grep | grep "sh /opt/ograc/common/script/ograc_daemon.sh")
if [ -n "${daemon_info}" ]; then
    logAndEchoInfo "daemon process info:\n ${daemon_info}"
    online_list[${#online_list[*]}]="ograc_daemon"
fi

systemctl is-active ograc.timer > /dev/null 2>&1
if [ $? -eq 0 ]; then
    online_list[${#online_list[*]}]="ograc_timer_active"
fi

systemctl is-enabled ograc.timer > /dev/null 2>&1
if [ $? -eq 0 ]; then
    online_list[${#online_list[*]}]="ograc_timer_enabled"
fi

systemctl is-active ograc_logs_handler.timer > /dev/null 2>&1
if [ $? -eq 0 ]; then
    online_list[${#online_list[*]}]="ograc_logs_handler_timer_active"
fi

systemctl is-enabled ograc_logs_handler.timer > /dev/null 2>&1
if [ $? -eq 0 ]; then
    online_list[${#online_list[*]}]="ograc_logs_handler_timer_enabled"
fi

logAndEchoInfo "check ograc complete."
