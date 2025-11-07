#!/bin/bash

DIR_PATH=$(cd `dirname $0`;pwd)
ROOT_PATH=$(cd ${DIR_PATH}/../../../;pwd)

function do_regress() {
    rm -rf ${ROOT_PATH}/../ograc_data/*
    set +e
    yum install lcov -y
    export part_name=$1
    export local_build=1
    time bash ${ROOT_PATH}/CI/build/script/run_ograc_test.sh ${part_name} 2>&1 | tee ${ROOT_PATH}/regress_output/LLT_log_\${part_name}.txt
    regress_start="========================= Run Regression ======================="
    regress_end="********************* END: og_regress *********************"
    awk "/\${regress_start}/{flag=1; next} /\${regress_end}/{flag=0} flag" ${ROOT_PATH}/regress_output/LLT_log_\${part_name}.txt > ${ROOT_PATH}/regress_output/LLT_result_\${part_name}.txt
    cat ${ROOT_PATH}/regress_output/LLT_result_\${part_name}.txt >> ${ROOT_PATH}/regress_output/LLT_result_all.txt
    set -e
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
do_regress "part1"

echo '====================================='
echo '[+] all LLT test has completed!'
echo '[+] testcase results:'
echo '    - $regress_output/LLT_results_part1/*'
echo '[+] script outputs:'
echo '    - regress_output/LLT_log_part1.txt'
echo '[+] LLT results:'
echo '    - regress_output/LLT_result_part1.txt'
echo '    - regress_output/LLT_result_all.txt'
regress_result=$(tail -n 1 $ROOT_PATH/regress_output/test_result.txt)
echo ${regress_result}