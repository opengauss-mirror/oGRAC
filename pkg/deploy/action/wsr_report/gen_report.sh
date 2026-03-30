#!/bin/bash
set +x

CURRENT_PATH=$(dirname $(readlink -f $0))
date_time=`date +"%Y%m%d%H%M%S"`
source ${CURRENT_PATH}/../env.sh
deploy_param_file=${CURRENT_PATH}/../config/deploy_param.json
ograc_port=$(python3 ${CURRENT_PATH}/get_config_info.py "ograc_port")
export OGRACD_PORT=${ograc_port}

function gen_wsr_report() {
    host_name=`hostname`
    kmc_log=`su -s /bin/bash - ${ograc_user} -c "ogsql ${ogsql_user_name}/${ogsql_user_passwd}@${ogsql_server_ip}:${ogsql_server_port} -q -c 'wsr list'" | grep KmcCheckKmcCtx`
    su -s /bin/bash - ${ograc_user} -c "ogsql ${ogsql_user_name}/${ogsql_user_passwd}@${ogsql_server_ip}:${ogsql_server_port} -q -c 'CALL WSR\$CREATE_SNAPSHOT'"
    sleep ${ogsql_snapshot_time}
    su -s /bin/bash - ${ograc_user} -c "ogsql ${ogsql_user_name}/${ogsql_user_passwd}@${ogsql_server_ip}:${ogsql_server_port} -q -c 'CALL WSR\$CREATE_SNAPSHOT'"
    if [ -z ${kmc_log} ]; then
        snap_id_1=`su -s /bin/bash - ${ograc_user} -c "ogsql ${ogsql_user_name}/${ogsql_user_passwd}@${ogsql_server_ip}:${ogsql_server_port} -q -c 'wsr list'" | sed -n '11p' | awk '{print $1}'`
        snap_id_2=`su -s /bin/bash - ${ograc_user} -c "ogsql ${ogsql_user_name}/${ogsql_user_passwd}@${ogsql_server_ip}:${ogsql_server_port} -q -c 'wsr list'" | sed -n '10p' | awk '{print $1}'`
    else
        snap_id_1=`su -s /bin/bash - ${ograc_user} -c "ogsql ${ogsql_user_name}/${ogsql_user_passwd}@${ogsql_server_ip}:${ogsql_server_port} -q -c 'wsr list'" | sed -n '12p' | awk '{print $1}'`
        snap_id_2=`su -s /bin/bash - ${ograc_user} -c "ogsql ${ogsql_user_name}/${ogsql_user_passwd}@${ogsql_server_ip}:${ogsql_server_port} -q -c 'wsr list'" | sed -n '11p' | awk '{print $1}'`
    fi
    su -s /bin/bash - ${ograc_user} -c "ogsql ${ogsql_user_name}/${ogsql_user_passwd}@${ogsql_server_ip}:${ogsql_server_port} -q -c 'wsr ${snap_id_1} ${snap_id_2} \"${report_output_dir}/ograc_wsr_${host_name}_${date_time}.html\"'"
}

function main() {
    source ${CURRENT_PATH}/report.cnf
    sed -i "s/ogsql_server_port=\"1611\"/ogsql_server_port=\"${ograc_port}\"/" ${CURRENT_PATH}/report.cnf
    if [ ! -d ${report_output_dir} ]; then
        mkdir -m 750 -p ${report_output_dir}
    fi
    chmod 770 ${report_output_dir}
    chown -h ${system_user_name}:${ograc_common_group} ${report_output_dir}
    if [ $? -ne 0 ]; then
        echo "creat dir failed, please check the config and permission of the dir."
        exit 1
    fi

    gen_wsr_report
    if [ $? -ne 0 ]; then
        echo "generate wsr report failed, please check the config and permission of the dir."
        rm -rf ${report_output_dir}/ograc_wsr_${ogsql_server_ip}_${date_time}.html
        exit 1
    fi
}

main