#!/bin/bash
source ~/.bashrc

USER=`whoami`
if [ "${USER}" = "root" ]
then
	if [ -n "${OGRAC_USER:-}" ]; then
		USER="${OGRAC_USER}"
	elif [ -n "${DSS_HOME:-}" ] && [ -e "${DSS_HOME}" ]; then
		USER=$(stat -c %U "${DSS_HOME}")
	elif [ -f /opt/ograc/action/ograc/install_config.json ]; then
		USER=$(grep '"U_USERNAME_AND_GROUP"' /opt/ograc/action/ograc/install_config.json | cut -d '"' -f 4 | sed 's/:.*//')
	else
		USER=$(stat -c %U "$(dirname "$(readlink -f "$0")")")
	fi
fi

DSS_BIN=dssserver
BIN_PATH=${DSS_HOME}/bin
SCRIPT_NAME=`basename $(readlink -f $0)`
CONN_PATH=UDS:${DSS_HOME}/.dss_unix_d_socket
PARM=$1
NODE_ID=$2
script_log=/dev/null

usage()
{
    echo "Usage:"
    echo "cmd:"
    echo "    $0 -start node_id: start dssserver"
    echo "    $0 -stop node_id: kill dssserver"
    echo "    $0 -stop_force node_id: kill dssserver by force"
    echo "    $0 -check node_id: check dssserver"
    echo "    $0 -reg node_id: register dssserver"
    echo "    $0 -kick node_id: unregister dssserver"
    echo "    $0 -isreg node_id: check whether dssserver is registered"
}

log()
{
    local time
    time=`date "+%Y-%m-%d %H:%M:%S"`
    echo "[$time][DSS]$1" >> "${script_log}" 2>&1
}

touch_logfile()
{
    local log_file=$1
    if [ ! -f "${log_file}" ]; then
        touch "${log_file}"
        chmod 600 "${log_file}"
    fi
}

clear_script_log()
{
    local _log_dir=$1
    local _log_name=$2
    local _max_log_backup=$3
    local log_num

    if [ -L "${_log_dir}" ]; then
        log_num=`find -L "${_log_dir}" -maxdepth 1 -type f -name "${_log_name}*" | wc -l`
        if [ "${log_num}" -ge "${_max_log_backup}" ]; then
            find -L "${_log_dir}" -maxdepth 1 -type f -name "${_log_name}*" | xargs ls -t {} 2>/dev/null | tail -n $(expr ${log_num} - ${_max_log_backup}) | xargs -i rm -f {}
        fi
    else
        log_num=`find "${_log_dir}" -maxdepth 1 -type f -name "${_log_name}*" | wc -l`
        if [ "${log_num}" -ge "${_max_log_backup}" ]; then
            find "${_log_dir}" -maxdepth 1 -type f -name "${_log_name}*" | xargs ls -t {} 2>/dev/null | tail -n $(expr ${log_num} - ${_max_log_backup}) | xargs -i rm -f {}
        fi
    fi
}

check_log_file()
{
    local log_path=$1
    local log_file=$2
    local operation=$3
    local MAX_LOG_SIZE=16777216
    local MAX_LOG_BACKUP=10
    local log_file_size

    if [ -f "${log_file}" ]; then
        log_file_size=$(ls -l "${log_file}" | awk '{print $5}')
        if [ "${log_file_size}" -ge "${MAX_LOG_SIZE}" ]; then
            mv -f "${log_file}" "${log_path}/${operation}-$(date +%Y-%m-%d_%H%M%S).log" 2>/dev/null
            clear_script_log "${log_path}" "${operation}-" "${MAX_LOG_BACKUP}"
        fi
    fi
}

init_script_log()
{
    local log_home=""

    if [[ -n "${DSS_HOME}" && -f "${DSS_HOME}/cfg/dss_inst.ini" ]]; then
        log_home=`cat ${DSS_HOME}/cfg/dss_inst.ini | sed s/[[:space:]]//g | grep -Eo "^LOG_HOME=.*" | awk -F '=' '{print $2}'`
    fi

    if [[ -n "${log_home}" ]]; then
        script_log=${log_home}/dss_contrl.log
    elif [[ -n "${DSS_HOME}" ]]; then
        script_log=${DSS_HOME}/dss_contrl.log
    else
        script_log=/dev/null
        return
    fi

    mkdir -p "$(dirname "${script_log}")" 2>/dev/null
    touch_logfile "${script_log}"
    check_log_file "$(dirname "${script_log}")" "${script_log}" "dss_contrl"
}

log_ps_diagnostic()
{
    local tag=$1
    local pid
    local ps_all
    local ps_filtered

    log "[${tag}]cmd=${PARM} node_id=${NODE_ID} user=${USER} dss_home=${DSS_HOME}"
    ps_all=`ps -fu ${USER} 2>/dev/null | grep -w ${DSS_BIN} | grep -v grep | grep -v ${SCRIPT_NAME}`
    ps_filtered=`ps -f f -u ${USER} 2>/dev/null | grep -w ${DSS_BIN} | grep "${DSS_HOME}" | grep -v grep | grep -v ${SCRIPT_NAME}`
    log "[${tag}]ps all ${DSS_BIN}: ${ps_all:-<empty>}"
    log "[${tag}]ps filtered by DSS_HOME: ${ps_filtered:-<empty>}"
    pid=`program_pid`
    log "[${tag}]program_pid=${pid:-<empty>}"
    if [[ -n "${pid}" && -r "/proc/${pid}/status" ]]; then
        log "[${tag}]proc state: $(grep ^State /proc/${pid}/status 2>/dev/null)"
    fi
}

program_pid()
{
    pid=`ps -f f -u ${USER} | grep -w ${DSS_BIN} | grep ${DSS_HOME} | grep -v grep | grep -v ${SCRIPT_NAME} | awk '{print $2}' | tail -1`
    echo ${pid}
}

program_status()
{
    local pid
    local state

    pid=`program_pid`
    if [[ -z ${pid} ]]; then
        echo ""
        return
    fi

    if [[ ! -r "/proc/${pid}/status" ]]; then
        echo ""
        return
    fi

    state=$(awk '/^State:/ {print $2; exit}' "/proc/${pid}/status" 2>/dev/null)
    echo "${state}"
}

function check_dss()
{
    local dss_status
    dss_status=$(program_status)
    if [[ -z ${dss_status} ]]
    then
        log "[CHECK]dssserver is offline."
        log_ps_diagnostic "CHECK"
        echo "RES_FAILED"
        return 1
    fi
    if [[ "${dss_status}" == "D" || "${dss_status}" == "T" || "${dss_status}" == "Z" ]]
    then
        log "[CHECK]dssserver is in bad state: ${dss_status}"
        log_ps_diagnostic "CHECK"
        echo "RES_EAGAIN"
        return 3
    fi
    return 0
}

function check_dss_config()
{
    log "[CONFIG]checking dss config under ${DSS_HOME}"
    if [[ ! -e ${DSS_HOME}/cfg/dss_inst.ini ]]
    then
        log "[CONFIG]${DSS_HOME}/cfg/dss_inst.ini NOT exist"
        echo "${DSS_HOME}/cfg/dss_inst.ini NOT exist"
        echo "RES_FAILED"
        exit 1
    fi

    if [[ ! -e ${DSS_HOME}/cfg/dss_vg_conf.ini ]]
    then
        log "[CONFIG]${DSS_HOME}/cfg/dss_vg_conf.ini NOT exist"
        echo "${DSS_HOME}/cfg/dss_vg_conf.ini NOT exist"
        echo "RES_FAILED"
        exit 1
    fi

    LSNR_PATH=`cat ${DSS_HOME}/cfg/dss_inst.ini | sed s/[[:space:]]//g |grep -Eo "^LSNR_PATH=.*" | awk -F '=' '{print $2}'`
    if [[ -z ${LSNR_PATH} ]]
    then
        log "[CONFIG]cannot find lsnr path in dss_inst.ini"
        echo "CANNOT find lsnr path."
        echo "RES_FAILED"
        exit 1
    fi
    CONN_PATH=UDS:${LSNR_PATH}/.dss_unix_d_socket
    log "[CONFIG]lsnr_path=${LSNR_PATH}, conn_path=${CONN_PATH}"
}

function scand_check()
{
    groups=`groups`
    echo $groups
    array=(${groups// / })
    for var in ${array[@]}
    do
        echo $var
        log "[SCAND]dsscmd scandisk -t block -p /dev/sd -u ${USER} -g ${var}"
        nohup dsscmd scandisk -t block -p /dev/sd -u $USER -g $var >> /dev/null 2>&1 &
        if [[ $? != 0 ]]
        then
            log "[SCAND]dsscmd scandisk failed, group=${var}"
            exit 1
        fi
    done
}

function start_dss()
{
    local pid
    check_dss_config
    reg
	if [ $? -ne 0 ]; then
            log "[START]register failed before start dssserver"
			echo "RES_FAILED"
			exit 1
	fi
    pid=`program_pid`
    if [[ -n ${pid} ]]; then
        log "[START]dssserver already running, pid=${pid}, dss_home=${DSS_HOME}"
    else
        log "[START]starting dssserver, bin=${BIN_PATH}/${DSS_BIN}, dss_home=${DSS_HOME}"
        nohup ${BIN_PATH}/${DSS_BIN} -D ${DSS_HOME} >> "${script_log}" 2>&1 &
        log "[START]nohup launched, new pid=$(program_pid)"
    fi
}

function stop_dss() {
    log "[STOP]stopping dssserver via dsscmd stopdss, dss_home=${DSS_HOME}"
    dsscmd stopdss
    result=$?
    if [[ ${result} != 0 ]]; then
        log "[STOP]dsscmd stopdss failed, result=${result}"
        echo "RES_FAILED"
        exit 1
    fi
    log "[STOP]dsscmd stopdss success"
    echo "RES_SUCCESS"
    exit 0
}

function stop_dss_by_force() {
    local pid
	res_count=`ps -u ${USER} | grep ${DSS_BIN}|grep -v grep |wc -l`
	echo "res_count = ${res_count}"
    log "[STOP_FORCE]dssserver count=${res_count}, user=${USER}, dss_home=${DSS_HOME}"
	if [ "$res_count" -eq "0" ]; then
        log "[STOP_FORCE]no dssserver process found"
		return 0
	elif [ "$res_count" -eq "1" ]; then
        pid=`ps -u ${USER} | grep ${DSS_BIN}|grep -v grep | awk '{print $1}'`
        log "[STOP_FORCE]kill dssserver pid=${pid}"
		ps -u ${USER} | grep ${DSS_BIN}|grep -v grep | awk '{print "kill -9 " $1}' |sh
		return 0
	else
		res_count=`ps -fu ${USER} | grep ${DSS_BIN} | grep ${DSS_HOME} | grep -v grep | wc -l`
		echo "res_count is ${res_count}"
        log "[STOP_FORCE]multiple dssserver, filtered count=${res_count}"
		if [ "$res_count" -eq "0" ]; then
			return 0
		elif [ "$res_count" -eq "1" ]; then
            pid=`ps -fu ${USER} | grep ${DSS_BIN} | grep ${DSS_HOME} | grep -v grep | awk '{print $2}'`
            log "[STOP_FORCE]kill filtered dssserver pid=${pid}"
			ps -fu ${USER} | grep ${DSS_BIN} | grep ${DSS_HOME} | grep -v grep | awk '{print "kill -9 " $2}' |sh
			return 0
		else
            log "[STOP_FORCE]stop by force failed, ambiguous process count=${res_count}"
            echo "res_count is ${res_count}, stop by force failed"
			return 1
		fi
	fi
}

function reg()
{
    scand_check
    LOCAL_INSTANCE_ID=`awk '/INST_ID/{print}' ${DSS_HOME}/cfg/dss_inst.ini | awk -F= '{print $2}' | xargs`
    if [[ -z ${LOCAL_INSTANCE_ID} ]]
    then
        log "[REG]cannot find inst id in dss_inst.ini"
        echo "RES_FAILED"
        return 1
    fi
    log "[REG]dsscmd reghl -D ${DSS_HOME}, inst_id=${LOCAL_INSTANCE_ID}"
    dsscmd reghl -D ${DSS_HOME} >> /dev/null 2>&1
    if [[ $? != 0 ]]
    then
        log "[REG]dsscmd reghl failed"
        echo "RES_EAGAIN"
        return 3
    fi
    log "[REG]register success"
    return 0
}

function kick()
{
    LOCAL_INSTANCE_ID=`awk '/INST_ID/{print}' ${DSS_HOME}/cfg/dss_inst.ini | awk -F= '{print $2}' | xargs`
    if [[ -z ${LOCAL_INSTANCE_ID} ]]
    then
        log "[KICK]cannot find inst id in dss_inst.ini"
        echo "RES_FAILED"
        exit 1
    fi
    log "[KICK]local_inst_id=${LOCAL_INSTANCE_ID}, target_node_id=${NODE_ID}"
    if [[ ${LOCAL_INSTANCE_ID} == ${NODE_ID} ]]
    then
        stop_dss_by_force
        log "[KICK]dsscmd unreghl -D ${DSS_HOME}"
        dsscmd unreghl -D ${DSS_HOME} >> /dev/null 2>&1
        if [[ $? != 0 ]]
        then
            log "[KICK]dsscmd unreghl failed"
            echo "RES_FAILED"
            exit 1
        fi
        echo "RES_SUCCESS"
        exit 0
    fi
    log "[KICK]dsscmd kickh -i ${NODE_ID} -D ${DSS_HOME}"
    dsscmd kickh -i ${NODE_ID} -D ${DSS_HOME} >> /dev/null 2>&1

    if [[ $? != 0 ]]
    then
        log "[KICK]dsscmd kickh failed"
        echo "RES_FAILED"
        exit 1
    fi
    echo "RES_SUCCESS"
    exit 0
}

function is_reg()
{
    log "[ISREG]dsscmd inq_reg -i ${NODE_ID} -D ${DSS_HOME}"
    dsscmd inq_reg -i ${NODE_ID} -D ${DSS_HOME} >> /dev/null 2>&1
    result=$?
    if [[ ${result} == 255 ]]
    then
        log "[ISREG]dsscmd inq_reg returned 255"
        echo "RES_EAGAIN"
		exit 3
    fi
    if [[ ${result} != 2 ]]
    then
        log "[ISREG]dsscmd inq_reg failed, result=${result}"
        echo "RES_FAILED"
        exit 1
    fi
    log "[ISREG]dssserver is registered"
    echo "RES_SUCCESS"
    exit 0
}

############################### main ###############################

if [ $#	-ne 2 ]; then
	usage
	exit 1
fi

init_script_log
if [[ "${PARM}" != "-check" ]]; then
    log "[MAIN]begin ${PARM}, node_id=${NODE_ID}, user=${USER}, dss_home=${DSS_HOME}, script=${SCRIPT_NAME}"
fi

case "${PARM}" in
	-start)
		start_dss
		;;
	-stop)
		stop_dss
		;;
	-stop_force)
		stop_dss_by_force
		;;
	-check)
		check_dss
        if [ $? -ne 0 ]; then
			exit 1
		fi
		;;
	-reg)
		reg
		if [ $? -ne 0 ]; then
			echo "RES_FAILED"
			exit 1
		fi
		;;
	-kick)
		kick
		;;
    -isreg)
		is_reg
		;;
	*)
		log "[MAIN]invalid parameter ${PARM}"
		echo "RES_FAILED"
		usage
		exit 1
		;;
esac

if [[ "${PARM}" != "-check" ]]; then
    log "[MAIN]${PARM} success"
fi
echo "RES_SUCCESS"
exit 0
