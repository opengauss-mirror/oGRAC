#!/bin/bash
source ~/.bashrc

SCRIPT_DIR=$(dirname $(readlink -f $0))
OGRAC_HOME=$(dirname $(dirname $(dirname ${SCRIPT_DIR})))
ACTION_DIR="${OGRAC_HOME}/action"
GET_CONFIG="${ACTION_DIR}/ograc_common/get_config_info.py"
BIND_CPU_SCRIPT="${ACTION_DIR}/ograc_common/cpu_bind.py"
CPU_CONFIG_FILE="${OGRAC_HOME}/ograc/cfg/cpu_config.json"
CPU_BIND_CONFIG="${ACTION_DIR}/ograc_common/cpu_bind_config.json"

dbuser=`whoami`
loguser=`whoami`
if [ "${dbuser}" = "root" ]
then
	dbuser=$(python3 ${GET_CONFIG} "deploy_user")
fi
running_mode=$(python3 ${GET_CONFIG} "M_RUNING_MODE")
exit_num_file="${OGRAC_HOME}/cms/cfg/exit_num.txt"
exit_num_dir="${OGRAC_HOME}/cms/cfg"
single_mode="multiple"
process_to_check="ogracd"
process_path=$OGDB_DATA
control_log=/dev/null

function log()
{
	local time
	time=`date "+%Y-%m-%d %H:%M:%S"`
	echo "[${time}][DB]$1" >> "${control_log}" 2>&1
}

function touch_logfile()
{
	local log_file=$1
	if [ ! -f "${log_file}" ]; then
		mkdir -p "$(dirname "${log_file}")" 2>/dev/null
		touch "${log_file}"
		chmod 600 "${log_file}"
	fi
}

function clear_script_log()
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

function check_log_file()
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

function init_control_log()
{
	if [[ -n "${OGDB_DATA}" ]]; then
		control_log="${OGDB_DATA}/log/cluster_control.log"
	else
		control_log=/dev/null
		return
	fi

	touch_logfile "${control_log}"
	check_log_file "${OGDB_DATA}/log" "${control_log}" "cluster_control"
}

function log_process_diagnostic()
{
	local tag=$1
	local ps_all
	local ps_filtered

	log "[${tag}]cmd=${parm} node_id=${node_id} dbuser=${dbuser} ogdb_data=${OGDB_DATA}"
	log "[${tag}]process_to_check=${process_to_check}, process_path=${process_path}"
	ps_all=`ps -fu ${dbuser} 2>/dev/null | grep ${process_to_check} | grep -vE '(grep|defunct)'`
	ps_filtered=`ps -fu ${dbuser} 2>/dev/null | grep ${process_to_check} | grep "${process_path}" | grep -vE '(grep|defunct)'`
	log "[${tag}]ps all ${process_to_check}: ${ps_all:-<empty>}"
	log "[${tag}]ps filtered by OGDB_DATA: ${ps_filtered:-<empty>}"
}

function ensure_cpu_config() {
	if [ -f "${CPU_CONFIG_FILE}" ]; then
		return
	fi
	if [ ! -f "${BIND_CPU_SCRIPT}" ]; then
		echo "Warning: bind_cpu_config.py not found: ${BIND_CPU_SCRIPT}" >&2
		return
	fi

	local cfg_dir=$(dirname "${CPU_CONFIG_FILE}")
	if [ ! -d "${cfg_dir}" ]; then
		mkdir -p "${cfg_dir}" 2>/dev/null || true
	fi

	if [ ! -f "${CPU_BIND_CONFIG}" ]; then
		echo "Initializing CPU bind config..." >&2
		python3 "${BIND_CPU_SCRIPT}" init_config 2>&1 || echo "Warning: init_config failed (rc=$?)" >&2
	fi
	echo "Generating cpu_config.json..." >&2
	if [ "${loguser}" = "root" ]; then
		su -s /bin/bash - "${dbuser}" -c "python3 ${BIND_CPU_SCRIPT}" 2>&1 || echo "Warning: bind_cpu_config failed (rc=$?)" >&2
	else
		python3 "${BIND_CPU_SCRIPT}" 2>&1 || echo "Warning: bind_cpu_config failed (rc=$?)" >&2
	fi

	if [ ! -f "${CPU_CONFIG_FILE}" ]; then
		echo "Warning: cpu_config.json was NOT generated at ${CPU_CONFIG_FILE}" >&2
	fi
}

function usage()
{
	echo "Usage:"
	echo "	    $0 -start node_id"
	echo "	    startup OGDB..."
	echo "	    $0 -stop node_id"
	echo "	    kill OGDB..."
	echo "      $0 -stop_force node_id"
	echo "      kill OGDB by force..."
	echo "	    $0 -check node_id"
	echo "	    check OGDB status..."
	echo "      $0 -init_exit_file node_id"
	echo "      $0 -inc_exit_num node_id"
}

function check_process()
{
	local res_count
	res_count=`ps -u ${dbuser} | grep ${process_to_check} |grep -vE '(grep|defunct)' |wc -l`
	if [ "$res_count" -eq "0" ]; then
		log "[CHECK]${process_to_check} is offline, count=${res_count}, dbuser=${dbuser}"
		log_process_diagnostic "CHECK"
		return 1
	elif [ "$res_count" -eq "1" ]; then
		return 0
	else
		res_count=`ps -fu ${dbuser} | grep ${process_to_check} | grep ${process_path} | grep -vE '(grep|defunct)' | wc -l`
		if [ "$res_count" -eq "0" ]; then
			log "[CHECK]no ${process_to_check} matched OGDB_DATA=${process_path}, count=${res_count}"
			log_process_diagnostic "CHECK"
			return 1
		elif [ "$res_count" -eq "1" ]; then
			return 0
		else
			log "[CHECK]ambiguous ${process_to_check} process count=${res_count}"
			log_process_diagnostic "CHECK"
			echo "res_count= ${res_count}"
			echo "RES_EAGAIN"
			return 1
		fi
	fi
	return 0
}

function start_ograc() {
	ensure_cpu_config
	numactl_str=" "
	set +e
	numactl --hardware > /dev/null 2>&1
	if [ $? -eq 0 ]; then
		OS_ARCH=$(uname -m)
		deploy_mode=$(python3 ${GET_CONFIG} "deploy_mode")
		if [[ ${OS_ARCH} =~ "aarch64" ]] && [[ x"${deploy_mode}" != x"dss" ]]; then
            CPU_CORES_NUM=`cat /proc/cpuinfo |grep "architecture" |wc -l`
            CPU_CORES_NUM=$((CPU_CORES_NUM - 1))
            numactl_str="numactl -C 0-1,6-11,16-"${CPU_CORES_NUM}" "
		fi

		if [[ ${OS_ARCH} =~ "aarch64" ]]; then
			result_str=$(python3 ${GET_CONFIG} "OGRAC_NUMA_CPU_INFO")
			if [ -z "$result_str" ]; then
				log "[START]OGRAC_NUMA_CPU_INFO is empty"
				echo "Error: OGRAC_NUMA_CPU_INFO is empty."
				exit 1
			fi
			numactl_str="numactl -C ${result_str}"
		fi
	fi
	set -e
	log "[START]starting ogracd, dbuser=${dbuser}, ogdb_data=${OGDB_DATA}"
	if [ "${loguser}" = "root" ]; then
		sudo  -E -i -u ${dbuser} sh -c "nohup ogracd -D \${OGDB_DATA} >> ${OGDB_DATA}/log/ogracstatus.log 2>&1 &"
		if [ $? -ne 0 ]; then
			log "[START]failed to launch ogracd as user ${dbuser}"
			echo "RES_FAILED"
			exit 1
		fi
	else
		nohup ogracd -D ${OGDB_DATA} >> ${OGDB_DATA}/log/ogracstatus.log 2>&1 &
		if [ $? -ne 0 ]; then
			log "[START]failed to launch ogracd"
			echo "RES_FAILED"
			exit 1
		fi
	fi
	log "[START]nohup ogracd launched, new pid check pending"
}

function stop_ograc() {
	local res_count
	res_count=`ps -u ${dbuser} | grep ${process_to_check} |grep -v grep |wc -l`
	echo "res_count = ${res_count}"
	log "[STOP]${process_to_check} count=${res_count}, dbuser=${dbuser}"
	if [ "$res_count" -eq "0" ]; then
		log "[STOP]${process_to_check} already stopped"
		echo "RES_FAILED"
		exit 1
	elif [ "$res_count" -eq "1" ]; then
		log "[STOP]kill ${process_to_check} pid=$(ps -u ${dbuser} | grep ${process_to_check}|grep -v grep | awk '{print $1}')"
		ps -u ${dbuser} | grep ${process_to_check}|grep -v grep | awk '{print "kill -9 " $1}' |sh
		echo "RES_SUCCESS"
		exit 0
	else
		res_count=`ps -fu ${dbuser} | grep ${process_to_check} | grep ${process_path} | grep -v grep | wc -l`
		echo "res_count is ${res_count}"
		log "[STOP]multiple ${process_to_check}, filtered count=${res_count}"
		if [ "$res_count" -eq "0" ]; then
			log "[STOP]no ${process_to_check} matched OGDB_DATA=${process_path}"
			echo "RES_FAILED"
			exit 1
		elif [ "$res_count" -eq "1" ]; then
			log "[STOP]kill filtered ${process_to_check} pid=$(ps -fu ${dbuser} | grep ${process_to_check} | grep ${process_path} | grep -v grep | awk '{print $2}')"
			ps -fu ${dbuser} | grep ${process_to_check} | grep ${process_path} | grep -v grep | awk '{print "kill -9 " $2}' |sh
			echo "RES_SUCCESS"
			exit 0
		else
			log "[STOP]ambiguous ${process_to_check} process count=${res_count}"
			echo "RES_EAGAIN"
			exit 3
		fi
	fi
}

function stop_ograc_by_force() {
	local res_count
	res_count=`ps -u ${dbuser} | grep ${process_to_check}|grep -v grep |wc -l`
	echo "res_count = ${res_count}"
	log "[STOP_FORCE]${process_to_check} count=${res_count}, dbuser=${dbuser}"
	if [ "$res_count" -eq "0" ]; then
		log "[STOP_FORCE]no ${process_to_check} process found"
		echo "RES_SUCCESS"
		exit 0
	elif [ "$res_count" -eq "1" ]; then
		log "[STOP_FORCE]kill ${process_to_check} pid=$(ps -u ${dbuser} | grep ${process_to_check}|grep -v grep | awk '{print $1}')"
		ps -u ${dbuser} | grep ${process_to_check}|grep -v grep | awk '{print "kill -9 " $1}' |sh
		echo "RES_SUCCESS"
		exit 0
	else
		res_count=`ps -fu ${dbuser} | grep ${process_to_check} | grep ${process_path} | grep -v grep | wc -l`
		echo "res_count is ${res_count}"
		log "[STOP_FORCE]multiple ${process_to_check}, filtered count=${res_count}"
		if [ "$res_count" -eq "0" ]; then
			log "[STOP_FORCE]no ${process_to_check} matched OGDB_DATA=${process_path}"
			echo "RES_SUCCESS"
			exit 0
		elif [ "$res_count" -eq "1" ]; then
			log "[STOP_FORCE]kill filtered ${process_to_check} pid=$(ps -fu ${dbuser} | grep ${process_to_check} | grep ${process_path} | grep -v grep | awk '{print $2}')"
			ps -fu ${dbuser} | grep ${process_to_check} | grep ${process_path} | grep -v grep | awk '{print "kill -9 " $2}' |sh
			echo "RES_SUCCESS"
			exit 0
		else
			log "[STOP_FORCE]ambiguous ${process_to_check} process count=${res_count}"
			echo "RES_EAGAIN"
			exit 3
		fi
	fi
}

function inc_exit_num() {
	if [ -d ${exit_num_dir} ]; then
		if [ ! -f ${exit_num_file} ]; then
	  		touch ${exit_num_file}
	  		if [ $? -eq 0 ]; then
	  		  	chmod 755 ${exit_num_file}
	  		  	echo 1 > ${exit_num_file}
	  		  	echo "create exit_num_file success"
				log "[INC_EXIT_NUM]create exit_num_file success"
				echo "RES_SUCCESS"
	  		  	exit 0
	  		else
	  		  	echo "create exit_num_file failed"
				log "[INC_EXIT_NUM]create exit_num_file failed"
				echo "RES_FAILED"
	  		  	exit 1
	  		fi
		else
		  	for num in `cat ${exit_num_file}`
		  	do
		  	  	num_new=$((${num}+1))
		  	  	echo ${num_new} > ${exit_num_file}
		  	done
			log "[INC_EXIT_NUM]increment exit_num to $(cat ${exit_num_file})"
		fi
	else
		echo "do not have exit_num dir"
		log "[INC_EXIT_NUM]exit_num dir not found: ${exit_num_dir}"
		exit 1
	fi
}

function init_exit_file() {
	if [ -d ${exit_num_dir} ]; then
		if [ ! -f ${exit_num_file} ]; then
			touch ${exit_num_file}
			  	if [ $? -eq 0 ]; then
			  		chmod 755 ${exit_num_file}
			  		echo 0 > ${exit_num_file}
					log "[INIT_EXIT_FILE]create exit_num_file success"
					echo "RES_SUCCESS"
			  		exit 0
			  	else
			  	  	echo "create exit_num_file failed"
					log "[INIT_EXIT_FILE]create exit_num_file failed"
					echo "RES_FAILED"
			  	  	exit 1
			  	fi
		else
		  	echo 0 > ${exit_num_file}
			log "[INIT_EXIT_FILE]reset exit_num_file to 0"
		fi
	else
		echo "do not have exit_num dir"
		log "[INIT_EXIT_FILE]exit_num dir not found: ${exit_num_dir}"
		exit 1
	fi
}

############################### main ###############################

if [ $#	-ne 2 ]; then
	usage
	exit 1
fi

parm=$1
node_id=$2
init_control_log
if [[ "${parm}" != "-check" ]]; then
	log "[MAIN]begin ${parm}, node_id=${node_id}, dbuser=${dbuser}, ogdb_data=${OGDB_DATA}, script=${SCRIPT_DIR}/$(basename $0)"
fi

case "${parm}" in
	-start)
		start_ograc
		;;
	-stop)
		stop_ograc
		;;
	-stop_force)
		stop_ograc_by_force
		;;
	-check)
		check_process
		if [ $? -ne 0 ]; then
			echo "RES_FAILED"
			exit 1
		fi
		;;
	-inc_exit_num)
		inc_exit_num
		;;
	-init_exit_file)
		init_exit_file
		;;
	*)
		log "[MAIN]invalid parameter ${parm}"
		echo "RES_FAILED"
		usage
		exit 1
		;;
esac

if [[ "${parm}" != "-check" ]]; then
	log "[MAIN]${parm} success"
fi
echo "RES_SUCCESS"
exit 0
