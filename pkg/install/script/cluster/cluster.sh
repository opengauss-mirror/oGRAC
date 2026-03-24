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
	res_count=`ps -u ${dbuser} | grep ${process_to_check} |grep -vE '(grep|defunct)' |wc -l`
	if [ "$res_count" -eq "0" ]; then
		return 1
	elif [ "$res_count" -eq "1" ]; then
		return 0
	else 
		res_count=`ps -fu ${dbuser} | grep ${process_to_check} | grep ${process_path} | grep -vE '(grep|defunct)' | wc -l`
		if [ "$res_count" -eq "0" ]; then
			return 1
		elif [ "$res_count" -eq "1" ]; then
			return 0
		else
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
		OS_ARCH=$(uname -i)
		deploy_mode=$(python3 ${GET_CONFIG} "deploy_mode")
		if [[ ${OS_ARCH} =~ "aarch64" ]] && [[ x"${deploy_mode}" != x"dss" ]]; then
            CPU_CORES_NUM=`cat /proc/cpuinfo |grep "architecture" |wc -l`
            CPU_CORES_NUM=$((CPU_CORES_NUM - 1))
            numactl_str="numactl -C 0-1,6-11,16-"${CPU_CORES_NUM}" "
		fi

		if [[ ${OS_ARCH} =~ "aarch64" ]]; then
			result_str=$(python3 ${GET_CONFIG} "OGRAC_NUMA_CPU_INFO")
			if [ -z "$result_str" ]; then
				echo "Error: OGRAC_NUMA_CPU_INFO is empty."
				exit 1
			fi
			numactl_str="numactl -C ${result_str}"
		fi
	fi
	set -e
	if [ "${loguser}" = "root" ]; then
		sudo  -E -i -u ${dbuser} sh -c "nohup ogracd -D \${OGDB_DATA} >> ${OGDB_DATA}/log/ogracstatus.log 2>&1 &"
		if [ $? -ne 0 ]; then 
			echo "RES_FAILED"
			exit 1
		fi
	else
		nohup ogracd -D ${OGDB_DATA} >> ${OGDB_DATA}/log/ogracstatus.log 2>&1 &
		if [ $? -ne 0 ]; then 
			echo "RES_FAILED"
			exit 1
		fi
	fi
}

function stop_ograc() {
	res_count=`ps -u ${dbuser} | grep ${process_to_check} |grep -v grep |wc -l`
	echo "res_count = ${res_count}"
	if [ "$res_count" -eq "0" ]; then
		echo "RES_FAILED"
		exit 1
	elif [ "$res_count" -eq "1" ]; then
		ps -u ${dbuser} | grep ${process_to_check}|grep -v grep | awk '{print "kill -9 " $1}' |sh
		echo "RES_SUCCESS"
		exit 0
	else 
		res_count=`ps -fu ${dbuser} | grep ${process_to_check} | grep ${process_path} | grep -v grep | wc -l`
		echo "res_count is ${res_count}"
		if [ "$res_count" -eq "0" ]; then
			echo "RES_FAILED"
			exit 1
		elif [ "$res_count" -eq "1" ]; then
			ps -fu ${dbuser} | grep ${process_to_check} | grep ${process_path} | grep -v grep | awk '{print "kill -9 " $2}' |sh
			echo "RES_SUCCESS"
			exit 0
		else
			echo "RES_EAGAIN"
			exit 3
		fi
	fi
}

function stop_ograc_by_force() {
	res_count=`ps -u ${dbuser} | grep ${process_to_check}|grep -v grep |wc -l`
	echo "res_count = ${res_count}"
	if [ "$res_count" -eq "0" ]; then
		echo "RES_SUCCESS"
		exit 0
	elif [ "$res_count" -eq "1" ]; then
		ps -u ${dbuser} | grep ${process_to_check}|grep -v grep | awk '{print "kill -9 " $1}' |sh
		echo "RES_SUCCESS"
		exit 0
	else
		res_count=`ps -fu ${dbuser} | grep ${process_to_check} | grep ${process_path} | grep -v grep | wc -l`
		echo "res_count is ${res_count}"
		if [ "$res_count" -eq "0" ]; then
			echo "RES_SUCCESS"
			exit 0
		elif [ "$res_count" -eq "1" ]; then
			ps -fu ${dbuser} | grep ${process_to_check} | grep ${process_path} | grep -v grep | awk '{print "kill -9 " $2}' |sh
			echo "RES_SUCCESS"
			exit 0
		else
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
				echo "RES_SUCCESS"
	  		  	exit 0
	  		else
	  		  	echo "create exit_num_file failed"
				echo "RES_FAILED"
	  		  	exit 1
	  		fi
		else
		  	for num in `cat ${exit_num_file}`
		  	do
		  	  	num_new=$((${num}+1))
		  	  	echo ${num_new} > ${exit_num_file}
		  	done
		fi
	else
		echo "do not have exit_num dir"
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
					echo "RES_SUCCESS"
			  		exit 0
			  	else
			  	  	echo "create exit_num_file failed"
					echo "RES_FAILED"
			  	  	exit 1
			  	fi
		else
		  	echo 0 > ${exit_num_file}
		fi
	else
		echo "do not have exit_num dir"
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
		echo "RES_FAILED"
		usage
		exit 1
		;;
esac

echo "RES_SUCCESS"
exit 0