#!/bin/bash

DIR_PATH=$(cd `dirname $0`;pwd)
ROOT_PATH=$(cd ${DIR_PATH}/../../../;pwd)
REGRESS_HOME=/home/regress/og_regress
RUN_TEST_USER=ogracdba

function cleanup_regress_install() {
    if [ -x ${REGRESS_HOME}/install/bin/uninstall.py ] && id ${RUN_TEST_USER} >/dev/null 2>&1; then
        su - ${RUN_TEST_USER} -c "python3 ${REGRESS_HOME}/install/bin/uninstall.py -U ${RUN_TEST_USER} -F -D ${REGRESS_HOME}/data -g withoutroot -d" || true
    fi

    pids=$(ps -eo pid,args | awk '/\/home\/regress\/og_regress/ && /(ogracd|cms)/ {print $1}')
    if [ -n "${pids}" ]; then
        kill -9 ${pids} >/dev/null 2>&1 || true
    fi

    if [ -f /home/${RUN_TEST_USER}/.bashrc ]; then
        sed -i '/\/home\/regress\/og_regress/d' /home/${RUN_TEST_USER}/.bashrc || true
        sed -i '/export OGDB_HOME=/d' /home/${RUN_TEST_USER}/.bashrc || true
    fi

    rm -rf ${REGRESS_HOME}
    rm -rf /home/regress/ograc_data/*
    rm -rf ${ROOT_PATH}/../ograc_data/*
}

function do_regress() {
    cleanup_regress_install
    set +e
    yum install lcov -y
    export part_name=$1
    export local_build=1
    log_file=${ROOT_PATH}/regress_output/LLT_log_${part_name}.txt
    result_file=${ROOT_PATH}/regress_output/LLT_result_${part_name}.txt
    echo "Test Result: ERROR" > ${ROOT_PATH}/regress_output/test_result.txt
    { time bash ${ROOT_PATH}/CI/build/script/run_ograc_test.sh ${part_name}; } 2>&1 | tee ${log_file}
    run_status=${PIPESTATUS[0]}
    regress_start="========================= Run Regression ======================="
    regress_end="********************* END: og_regress *********************"
    awk -v start="${regress_start}" -v end="${regress_end}" 'index($0, start) {flag=1; next} index($0, end) {flag=0} flag' ${log_file} > ${result_file}
    cat ${result_file} >> ${ROOT_PATH}/regress_output/LLT_result_all.txt
    part_result=$(tail -n 1 ${ROOT_PATH}/regress_output/test_result.txt)
    set -e
    if [ ${run_status} -ne 0 ] || [ "${part_result}" != "Test Result: Success" ]; then
        echo "Test Result: ERROR" > ${ROOT_PATH}/regress_output/test_result.txt
        return 1
    fi
}


mkdir -p ${ROOT_PATH}/regress_output/
rm -rf ${ROOT_PATH}/regress_output/*
mkdir -p ${ROOT_PATH}/lcov_output/
rm -rf ${ROOT_PATH}/lcov_output/*
echo "" > ${ROOT_PATH}/regress_output/LLT_result_all.txt
if [ -n "$1" ]; then
    # 如果存在，将其赋值给环境变量 pass_build
    export pass_build="$1"
    echo "pass_build is set to: $pass_build"
fi
regress_result="Test Result: ERROR";
echo ${regress_result} > ${ROOT_PATH}/regress_output/test_result.txt
if ! do_regress "part_all"; then
    exit 1
fi
cleanup_regress_install

echo '====================================='
echo '[+] all LLT test has completed!'
echo '[+] testcase results:'
echo '    - $regress_output/LLT_results_part_all/*'
echo '[+] script outputs:'
echo '    - regress_output/LLT_log_part_all.txt'
echo '[+] LLT results:'
echo '    - regress_output/LLT_result_part_all.txt'
echo '    - regress_output/LLT_result_all.txt'
regress_result=$(tail -n 1 $ROOT_PATH/regress_output/test_result.txt)
echo ${regress_result}
