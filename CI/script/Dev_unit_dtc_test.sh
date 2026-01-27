#!/bin/bash
DIR_PATH=$(cd `dirname $0`;pwd)
code_path=$(cd ${DIR_PATH}/../../;pwd)
BASHRC_ORIGIN_NUM=$(sed -n '$=' /home/ogracdba/.bashrc)
export OGDB_HOME=/home/ogracdb/install
echo export OGSQL_SSL_QUIET=TRUE >> /home/ogracdba/.bashrc
echo export OGDB_HOME=/home/ogracdb/install >> /home/ogracdba/.bashrc
echo export sys_user_passwd='mHmNxBvw7Uu7LtSvrUIy8NY9womwIuJG9vAlMl0+zNifU7x5TnIz5UOqmkozbTyW' >> /home/ogracdba/.bashrc
GRUN_LOG=${code_path}/dtc_gtest_run.log
rm -rf ${GRUN_LOG}
echo "DTC_GRUN_LOG: ${GRUN_LOG}"

kill_ogracdb()
{
    ps -ef |grep ogracd |grep -v grep |awk '{print $2}' |xargs kill -9
    sleep 2
    ps -ef |grep cms |grep -v grep |awk '{print $2}' |xargs kill -9
    sleep 2
}

init_og_regress()
{
    echo "=============== Initialize the Regression Program =============="
    kill_ogracdb
    rm -rf ${OGDB_HOME}
    mkdir -p ${OGDB_HOME}/data
    mkdir -p ${OGDB_HOME}/cfg
    mkdir -p ${OGDB_HOME}/log
    mkdir -p ${OGDB_HOME}/protect
    chmod 755 ${OGDB_HOME} -R

    echo JOB_QUEUE_PROCESSES = 0 >> ${OGDB_HOME}/cfg/ogracd.ini
    echo STATS_LEVEL = BASIC >> ${OGDB_HOME}/cfg/ogracd.ini
    echo CLUSTER_DATABASE = TRUE >> ${OGDB_HOME}/cfg/ogracd.ini
    echo INTERCONNECT_ADDR = 127.0.0.1 >> ${OGDB_HOME}/cfg/ogracd.ini
    echo INTERCONNECT_PORT = 1601 >> ${OGDB_HOME}/cfg/ogracd.ini
    echo INTERCONNECT_TYPE = TCP >> ${OGDB_HOME}/cfg/ogracd.ini
    echo INSTANCE_ID = 0 >> ${OGDB_HOME}/cfg/ogracd.ini
    echo LOG_HOME = ${OGDB_HOME}/log >> ${OGDB_HOME}/cfg/ogracd.ini
    echo MES_POOL_SIZE = 16384 >> ${OGDB_HOME}/cfg/ogracd.ini
    echo LSNR_ADDR = 127.0.0.1   >> ${OGDB_HOME}/cfg/ogracd.ini
    echo LSNR_PORT = 1611 >> ${OGDB_HOME}/cfg/ogracd.ini
    echo _LOG_LEVEL = 16712567 >> ${OGDB_HOME}/cfg/ogracd.ini
    echo USE_NATIVE_DATATYPE = TRUE >> ${OGDB_HOME}/cfg/ogracd.ini
    echo _SYS_PASSWORD = pkAqfAUA0AdWc/O/W13ODhC9+5o+V1fWhXHm1kGv7z79S/GQyydsJFnLix8jBrY43bdNMsPJmYfwziCSpxgASC3Hi+3eq+C4lsCxy5dDimVWGWTGNfwpfA== >> ${OGDB_HOME}/cfg/ogracd.ini
    echo ENABLE_SYSDBA_LOGIN = TRUE >> ${OGDB_HOME}/cfg/ogracd.ini
    echo UPPER_CASE_TABLE_NAMES = FALSE >> ${OGDB_HOME}/cfg/ogracd.ini
    echo CPU_GROUP_INFO = 0 >> ${OGDB_HOME}/cfg/ogracd.ini
    echo MAX_COLUMN_COUNT = 4096 >> ${OGDB_HOME}/cfg/ogracd.ini
    echo INTERCONNECT_BY_PROFILE = TRUE >> ${OGDB_HOME}/cfg/ogracd.ini
    echo ENABLE_FDSA = TRUE >> ${OGDB_HOME}/cfg/ogracd.ini
}

init_and_start_cms1()
{
    rm -rf /home/cms
	mkdir -p /home/cms
	dd if=/dev/zero of=/home/cms/gcc_file bs=100M count=1
    export CMS_HOME=${OGDB_HOME}
	echo export CMS_HOME=${OGDB_HOME} >> /home/ogracdba/.bashrc
	rm -rf ${CMS_HOME}/cfg/cms.ini
	echo NODE_ID = 0 >> ${CMS_HOME}/cfg/cms.ini
	echo GCC_HOME = /home/cms/gcc_file >> ${CMS_HOME}/cfg/cms.ini
    echo GCC_TYPE = FILE >> ${CMS_HOME}/cfg/cms.ini
    echo _IP = 127.0.0.1 >> ${CMS_HOME}/cfg/cms.ini
    echo _PORT = 1720 >> ${CMS_HOME}/cfg/cms.ini
    echo _DISK_DETECT_FILE = gcc_file >> ${CMS_HOME}/cfg/cms.ini
    chmod -R 777 /home/cms/
    chown -R ogracdba:ogracdba /home/cms/
    chmod -R 777 ${CMS_HOME}/
    chown -R ogracdba:ogracdba ${CMS_HOME}/
	su - ogracdba -c 'cms gcc -reset -f' 2>&1
	su - ogracdba -c 'cms node -add 0 node0 127.0.0.1 1720' 2>&1
	su - ogracdba -c 'cms res -add db -type db -attr "check_timeout=1000000000"' 2>&1
    su - ogracdba -c 'cms res -edit db -attr "HB_TIMEOUT=1000000000"' 2>&1
    su - ogracdba -c 'cms node -list' 2>&1
	su - ogracdba -c 'cms res -list' 2>&1
    echo "start to start cms 1"   
    nohup su - ogracdba -c 'cms server -start' 2>&1  &
}

cp_ograc_add_ons()
{
    mkdir -p $1/add-ons
    cp -d ${code_path}/library/pcre/lib/libpcre2-8.so*     $1/add-ons/
    cp -d ${code_path}/library/zlib/lib/libz.so*     $1/add-ons/
    cp -d ${code_path}/library/Zstandard/lib/libzstd.so*     $1/add-ons/
    cp -d ${code_path}/library/lz4/lib/liblz4.so*     $1/add-ons/
}

cp_ograc_bin()
{
    mkdir -p $1/bin
    cp ${code_path}/output/bin/ogracd $1/bin/
    cp ${code_path}/output/bin/cms $1/bin/
    cp ${code_path}/output/bin/ogbackup $1/bin/
    cp ${code_path}/output/bin/ogsql $1/bin/
    cp ${code_path}/output/bin/ogbox $1/bin/
    cp ${code_path}/output/bin/ogencrypt $1/bin/
    cp ${code_path}/library/Zstandard/bin/zstd $1/bin/

    cp ${code_path}/pkg/install/installdb.sh  $1/bin/
    cp ${code_path}/pkg/install/shutdowndb.sh  $1/bin/
    cp ${code_path}/pkg/install/sql_process.py  $1/bin/
    cp ${code_path}/pkg/install/uninstall.py  $1/bin/
    cp ${code_path}/pkg/install/script/cluster/cluster.sh  $1/bin/
}

cp_ograc_lib()
{
    mkdir -p $1/lib
    cp ${code_path}/output/lib/libogclient.so $1/lib/
    cp ${code_path}/output/lib/libogcommon.so $1/lib/
    cp ${code_path}/output/lib/libogprotocol.so $1/lib/
}

install_ogracdb()
{
    echo "========================= Install ogracDB ======================="
    echo "################    copy new lib     #######################"

    if [ ! -d ${OGDB_HOME} ];then
	    mkdir -p ${OGDB_HOME}
    fi

    rm -rf ${OGDB_HOME}/add-ons
    rm -rf ${OGDB_HOME}/bin
    rm -rf ${OGDB_HOME}/lib
	rm -rf ${OGDB_HOME}/admin
    # tar -zxvf ${code_path}/output/bin/oGRAC-DATABASE-LINUX-64bit/oGRAC-RUN-LINUX-64bit.tar.gz -C ${OGDB_HOME}
    # cp -rf ${OGDB_HOME}/oGRAC-RUN-LINUX-64bit/add-ons     ${OGDB_HOME}
    # cp -rf ${OGDB_HOME}/oGRAC-RUN-LINUX-64bit/bin         ${OGDB_HOME}
    # cp -rf ${OGDB_HOME}/oGRAC-RUN-LINUX-64bit/lib         ${OGDB_HOME}
    # cp -rf ${OGDB_HOME}/oGRAC-RUN-LINUX-64bit/admin       ${OGDB_HOME}
    # cp -rf ${OGDB_HOME}/oGRAC-RUN-LINUX-64bit/package.xml ${OGDB_HOME}

    # rm -rf ${OGDB_HOME}/oGRAC-RUN-LINUX-64bit
    cp_ograc_add_ons /home/ogracdb/install
    cp_ograc_bin /home/ogracdb/install
    cp_ograc_lib /home/ogracdb/install
    cp -R ${code_path}/pkg/admin  ${OGDB_HOME}/

    export OGDB_HOME=/home/ogracdb/install
    export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${code_path}/output/lib/:${code_path}/library/gtest/lib/:${OGDB_HOME}/add-ons:${OGDB_HOME}/lib:${OGDB_HOME}/add-ons/nomlnx
    echo export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${code_path}/output/lib/:${code_path}/library/gtest/lib/:${OGDB_HOME}/add-ons:${OGDB_HOME}/lib:${OGDB_HOME}/add-ons/nomlnx >> /home/ogracdba/.bashrc
    echo export PATH=${OGDB_HOME}/bin:$PATH >> /home/ogracdba/.bashrc

    echo "copy linux lib complate!!"   
    echo "start to init cms 1"   
    init_and_start_cms1

    echo "Start ogracd with nomount:"
    UNAME=$(uname -a)
    if [[ "${UNAME}" =~ .*aarch64.* ]];then
        echo export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${code_path}/library/xnet/lib_arm/ >> /home/ogracdba/.bashrc
    elif [[ "${UNAME}" =~ .*x86_64.* ]];then
        echo export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${code_path}/library/xnet/lib/ >> /home/ogracdba/.bashrc
    else
        error "error: unknown arch!"
    fi
}

function error(){
    BASHRC_AFTER_NUM=$(sed -n '$=' /home/ogracdba/.bashrc)
    sed $(($BASHRC_ORIGIN_NUM+1)),${BASHRC_AFTER_NUM}d -i /home/ogracdba/.bashrc
    echo $1
    echo $1 >> ${GRUN_LOG} 2>&1
    exit 1
}

make_code()
{
    echo -n "make test ..."
    lcov_build_flag=""

    cd ${code_path}/build/
    sh Makefile.sh clean 2>&1 

    if [ "${LCOV_ENABLE}" = TRUE ]
    then
        lcov_build_flag="lcov=1"
    fi

    sh Makefile.sh make_regress_test ${lcov_build_flag} 2>&1 
    if [ "$?" != "0" ]; then
        error "make package error!"
    fi

    cd ${code_path}/build
    source ./common.sh
    cd ${code_path}/build/pkg/test/unit_test/testcase/
    strip -N main ${OGRACDB_LIB}/libogserver.a 2>&1
    make -sj 8 2>&1 
    cd ${code_path}/build/pkg/test/unit_test/ut/mes
    make -sj 8 >> ${GRUN_LOG} 2>&1
    if [ "$?" != "0" ]; then
        error "make test error!"
    fi
    chown -R ogracdba:ogracdba ${code_path}/build/pkg/
}

run_dtc_test()
{
    echo
    echo -n "run dtc_test ..."
    if [[ ! -d "${code_path}/gtest_result" ]]
    then 
	    mkdir -p ${code_path}/gtest_result
    fi
    chown -R ogracdba:ogracdba ${code_path}/gtest_result
    su - ogracdba -c "${code_path}/output/bin/dtc_test --gtest_output=xml:${code_path}/gtest_result/" 2>&1 | tee -a ${GRUN_LOG}
    su - ogracdba -c "${code_path}/output/bin/mes_test --gtest_output=xml:${code_path}/gtest_result/" 2>&1 | tee -a ${GRUN_LOG}
    succ_num=`cat ${GRUN_LOG} | grep '\[  PASSED  ]' | wc -l`
    err_num=`cat ${GRUN_LOG} | grep '\[  FAILED  ]' | wc -l`
    if [ $succ_num -ne 2 ] || [ $err_num -ne 0 ]; then
        error "something wrong when run dtc_test!"
    fi
    echo
    echo "run dtc_test success!"
    BASHRC_AFTER_NUM=$(sed -n '$=' /home/ogracdba/.bashrc)
    sed $(($BASHRC_ORIGIN_NUM+1)),${BASHRC_AFTER_NUM}d -i /home/ogracdba/.bashrc
}

gen_lcov_report()
{
    if [[ ! -d "${code_path}/lcov_output" ]]
    then 
	    mkdir -p ${code_path}/lcov_output
    fi
    coverage_info_name="${code_path}/lcov_output/dtc_test_coverage.info"
    coverage_report_name="${code_path}/lcov_output/dtc_test_coverage.report"
    find ${code_path}/ -name "*.gcno" | xargs touch
    lcov --capture --directory ${code_path}/ --rc lcov_branch_coverage=1 --output-file "${coverage_info_name}" 
    lcov -l --rc lcov_branch_coverage=1 "${coverage_info_name}" > "${coverage_report_name}" 
    # Reset all execution counts to zero
    lcov -d ${code_path}/ -z
    echo ">>>>>>>>>>>>>>>>>>>>> dtc utest lcov report successfully <<<<<<<<<<<<<<<<<<<<<<<<<<<"
}

main()
{
    LCOV_ENABLE=FALSE
    for arg in "$@"
    do 
        echo "arg is ${arg}"
        if [ ${arg} = "--coverage" ]
        then 
            echo "Enable coverage detection."
            LCOV_ENABLE=TRUE
        fi
    done

    init_og_regress
    make_code
    install_ogracdb
    run_dtc_test

    if [ "${LCOV_ENABLE}" = TRUE ]
    then 
        gen_lcov_report
    fi
}

main "$@"