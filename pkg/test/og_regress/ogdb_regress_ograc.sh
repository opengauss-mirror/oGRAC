#!/bin/bash

install_dir=$1
sys_passwd=$2
og_schedule_list=$3

ogsql=${install_dir}/bin/ogsql

prepare_result_dirs() {
   schedule_path=$1
   results_dir=$2
   mkdir -p "${results_dir}"
   while IFS= read -r line; do
      case "${line}" in
         test:*|INTERACT:*)
            cases=${line#*:}
            for test_name in ${cases}; do
               test_dir=$(dirname "${test_name}")
               if [ "${test_dir}" != "." ]; then
                  mkdir -p "${results_dir}/${test_dir}"
               fi
            done
            ;;
      esac
   done < "${schedule_path}"
}

schedule_has_failure() {
   local schedule_log=$1
   grep -Eq ":  FAILED|Result:  FAILED" "${schedule_log}"
}

rm -rf ./results/*
rm -rf ${install_dir}/cumu_*.bak*
rm -rf ${install_dir}/ogracdb_*.bak*
export OGSQL_SSL_QUIET=TRUE

run_status=0
schedule_names=()
IFS=',' read -ra raw_schedule_names <<< "${og_schedule_list}"
for schedule_name in "${raw_schedule_names[@]}"; do
   schedule_name=$(echo "${schedule_name}" | xargs)
   if [ -n "${schedule_name}" ]; then
      schedule_names+=("${schedule_name}")
   fi
done

if [ ${#schedule_names[@]} -eq 0 ]; then
   echo "No schedule file specified."
   exit 1
fi

for schedule_name in "${schedule_names[@]}"; do
   schedule_file=./${schedule_name}
   if [ ! -f "${schedule_file}" ]; then
      echo "Schedule file not found: ${schedule_file}"
      run_status=1
      break
   fi

   results_dir="./results/"
   if [ ${#schedule_names[@]} -gt 1 ]; then
      results_dir="./results/${schedule_name}/"
   fi
   prepare_result_dirs "${schedule_file}" "${results_dir}"
   schedule_log="./results/${schedule_name}.log"
   ./og_regress --bindir=${ogsql} --user=sys/${sys_passwd} --host=127.0.0.1 --port=1611 --inputdir=./sql/ --outputdir=${results_dir} --expectdir=./expected/ --schedule=${schedule_file} 2>&1 | tee "${schedule_log}"
   regress_status=${PIPESTATUS[0]}
   if [ ${regress_status} -ne 0 ] || schedule_has_failure "${schedule_log}"; then
      run_status=1
   fi
done

if [ ${run_status} -eq 0 ];then
   echo "    og_regress        :  OK"
   echo "********************* END: og_regress *********************"
else
   echo "    og_regress        :  FAILED"
   echo "********************* END: og_regress *********************"
fi
