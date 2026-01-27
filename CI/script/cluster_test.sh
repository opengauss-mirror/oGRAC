#!/bin/sh
DIR_PATH=$(cd `dirname $0`;pwd)
code_path=$(cd ${DIR_PATH}/../../;pwd)
regress_path=${code_path}/pkg/test/og_regress
script_path=${code_path}/CI/script
mkdir /home/ogracdba/tmp -p
tmp_file_path=/home/ogracdba/tmp
report_file=$tmp_file_path/regress.log
rm -rf $tmp_file_path/*
BASHRC_ORIGIN_NUM=$(sed -n '$=' /home/ogracdba/.bashrc)
echo export OGDB_HOME=/home/ogracdb/install >> /home/ogracdba/.bashrc
echo export OGDB_HOME_1=/home/ogracdb1/install >> /home/ogracdba/.bashrc
echo export sys_user_passwd='mHmNxBvw7Uu7LtSvrUIy8NY9womwIuJG9vAlMl0+zNifU7x5TnIz5UOqmkozbTyW' >> /home/ogracdba/.bashrc
echo export OGSQL_SSL_QUIET=TRUE >> /home/ogracdba/.bashrc
export OGDB_HOME=/home/ogracdb/install
export OGDB_HOME_1=/home/ogracdb1/install
PORT=`/sbin/ifconfig -a|grep inet|grep -v 127.0.0.1|grep -v inet6|awk '{print $2}'|tr -d "addr:" |head -n 1`
echo export PORT=${PORT} >> /home/ogracdba/.bashrc
collect_core()
{
    BASHRC_AFTER_NUM=$(sed -n '$=' /home/ogracdba/.bashrc)
    sed $(($BASHRC_ORIGIN_NUM+1)),${BASHRC_AFTER_NUM}d -i /home/ogracdba/.bashrc
	files=/home/core/ogracDB_`date +%Y-%m-%d-%H-%M-%S`
	mkdir -p ${files}
	# cp -r ${code_path}/pkg/bin ${files}/
	# cp -r ${code_path}/pkg/lib ${files}/
	mkdir -p ${files}/ogracdb0
	mkdir -p ${files}/ogracdb1
	cp -r ${OGDB_HOME}/add-ons ${files}/ogracdb0
	cp -r ${OGDB_HOME}/bin ${files}/ogracdb0
	cp -r ${OGDB_HOME}/cfg ${files}/ogracdb0
	cp -r ${OGDB_HOME}/lib ${files}/ogracdb0
	cp -r ${OGDB_HOME}/log ${files}/ogracdb0

	cp -r ${OGDB_HOME}/cfg ${files}/ogracdb1
	cp -r ${OGDB_HOME_1}/log ${files}/ogracdb1
    cp /home/ogsql.log ${files}/
    cp ${report_file} ${files}/

    tar -zcf ${files}.tar.gz  ${files}
    mv ${files}.tar.gz ${files}.tar.gz.log
    mkdir -p /home/regress/ograc/build_test/logs/
    ls -l /home/core
    cp -r /home/core/* /home/regress/ograc/build_test/logs/
    ls -l /home/regress/ograc/build_test/logs/
}

log()
{
    echo
    echo
    echo $1
}

kill_ogracdb()
{
    ps -ef |grep ogracd |grep -v grep |awk '{print $2}' |xargs kill -9
    sleep 2
    ps -ef |grep cms |grep -v grep |awk '{print $2}' |xargs kill -9
    sleep 2

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
	su - ogracdba -c 'cms gcc -reset -f' >> $report_file
	su - ogracdba -c 'cms node -add 0 node0 127.0.0.1 1720' >> $report_file
	su - ogracdba -c 'cms node -add 1 node1 127.0.0.1 1721' >> $report_file
	su - ogracdba -c 'cms res -add db -type db -attr "check_timeout=10"'>> $report_file
    su - ogracdba -c 'cms node -list' >> $report_file
	su - ogracdba -c 'cms res -list' >> $report_file
    echo "start to start cms 1"   
    nohup su - ogracdba -c 'cms server -start' >> $report_file  2>&1 &
}

init_and_start_cms2()
{
    export CMS_HOME=${OGDB_HOME_1}
	rm -rf ${CMS_HOME}/cfg/cms.ini
	echo NODE_ID = 1 >> ${CMS_HOME}/cfg/cms.ini
	echo GCC_HOME = /home/cms/gcc_file >> ${CMS_HOME}/cfg/cms.ini
    echo GCC_TYPE = FILE >> ${CMS_HOME}/cfg/cms.ini
    echo _IP = 127.0.0.1 >> ${CMS_HOME}/cfg/cms.ini
    echo _PORT = 1721 >> ${CMS_HOME}/cfg/cms.ini
    echo _DISK_DETECT_FILE = gcc_file >> ${CMS_HOME}/cfg/cms.ini
    chmod -R 777 ${CMS_HOME}/
    chown -R ogracdba:ogracdba ${CMS_HOME}/
    echo "start to start cms 2"   
    nohup su - ogracdba -c 'cms server -start' >> $report_file  2>&1 &
}

init_og_regress()
{
    log "=============== Initialize the Regression Program =============="
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
    echo "INTERCONNECT_ADDR = 127.0.0.1;${PORT}" >> ${OGDB_HOME}/cfg/ogracd.ini
    echo INTERCONNECT_PORT = 1601,1602 >> ${OGDB_HOME}/cfg/ogracd.ini
    echo INTERCONNECT_TYPE = TCP >> ${OGDB_HOME}/cfg/ogracd.ini
    echo INSTANCE_ID = 0 >> ${OGDB_HOME}/cfg/ogracd.ini
    echo MES_POOL_SIZE = 16384 >> ${OGDB_HOME}/cfg/ogracd.ini
    echo LSNR_ADDR = 127.0.0.1   >> ${OGDB_HOME}/cfg/ogracd.ini
    echo LSNR_PORT = 1611 >> ${OGDB_HOME}/cfg/ogracd.ini
    echo _LOG_LEVEL = 16712567 >> ${OGDB_HOME}/cfg/ogracd.ini
    echo USE_NATIVE_DATATYPE = TRUE >> ${OGDB_HOME}/cfg/ogracd.ini
    echo _SYS_PASSWORD = pkAqfAUA0AdWc/O/W13ODhC9+5o+V1fWhXHm1kGv7z79S/GQyydsJFnLix8jBrY43bdNMsPJmYfwziCSpxgASC3Hi+3eq+C4lsCxy5dDimVWGWTGNfwpfA== >> ${OGDB_HOME}/cfg/ogracd.ini

    rm -rf ${OGDB_HOME_1}
    mkdir -p ${OGDB_HOME_1}/cfg
    mkdir -p ${OGDB_HOME_1}/log
    mkdir -p ${OGDB_HOME_1}/protect
    chmod 755 ${OGDB_HOME_1} -R

    echo JOB_QUEUE_PROCESSES = 0 >> ${OGDB_HOME_1}/cfg/ogracd.ini
    echo STATS_LEVEL = BASIC >> ${OGDB_HOME_1}/cfg/ogracd.ini
    echo CLUSTER_DATABASE = TRUE >> ${OGDB_HOME_1}/cfg/ogracd.ini
    echo "INTERCONNECT_ADDR = 127.0.0.1;${PORT}" >> ${OGDB_HOME_1}/cfg/ogracd.ini
    echo INTERCONNECT_PORT = 1601,1602 >> ${OGDB_HOME_1}/cfg/ogracd.ini
    echo INTERCONNECT_TYPE = TCP >> ${OGDB_HOME_1}/cfg/ogracd.ini
    echo INSTANCE_ID = 1 >> ${OGDB_HOME_1}/cfg/ogracd.ini
    echo MES_POOL_SIZE = 16384 >> ${OGDB_HOME_1}/cfg/ogracd.ini
    echo LSNR_ADDR = ${PORT}   >> ${OGDB_HOME_1}/cfg/ogracd.ini
    echo LSNR_PORT = 1612 >> ${OGDB_HOME_1}/cfg/ogracd.ini
    echo _LOG_LEVEL = 16712567 >> ${OGDB_HOME_1}/cfg/ogracd.ini
    echo USE_NATIVE_DATATYPE = TRUE >> ${OGDB_HOME_1}/cfg/ogracd.ini
    echo _SYS_PASSWORD = pkAqfAUA0AdWc/O/W13ODhC9+5o+V1fWhXHm1kGv7z79S/GQyydsJFnLix8jBrY43bdNMsPJmYfwziCSpxgASC3Hi+3eq+C4lsCxy5dDimVWGWTGNfwpfA== >> ${OGDB_HOME_1}/cfg/ogracd.ini

    echo CONTROL_FILES = ${OGDB_HOME}/data/ctrl1, ${OGDB_HOME}/data/ctrl2, ${OGDB_HOME}/data/ctrl3 >> ${OGDB_HOME_1}/cfg/ogracd.ini
}

make_code()
{
    log "==================== Begin Rebuild ogracKernel ================="
    lcov_build_flag=""
    if [ "${LCOV_ENABLE}" = TRUE ]
    then
        lcov_build_flag="lcov=1"
    fi
    cd ${code_path}/build
    sh Makefile.sh clean
    sh Makefile.sh make_regress_test ${lcov_build_flag}
    if [ "$?" != "0" ]; then
        error "make package error!"
    fi
    cd ${code_path}/build
    source ./common.sh
    cd ${code_path}/build/pkg/test/cluster_test
    strip -N main ${OGRACDB_LIB}/libogserver.a
    make -sj 8
    if [ "$?" != "0" ]; then
        echo "make test error!"
        exit 1
    fi
    chown -R ogracdba:ogracdba ${code_path}/build/pkg/
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
    echo "################    cp_ograc_bin     #######################"
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
    log "========================= Install ogracDB ======================="
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

    echo export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:${OGDB_HOME}/add-ons/nomlnx:${OGDB_HOME}/add-ons:${OGDB_HOME}/lib >> /home/ogracdba/.bashrc
    echo export PATH=${OGDB_HOME}/bin:$PATH >> /home/ogracdba/.bashrc

    if [ ! -d ${OGDB_HOME_1} ];then
        mkdir -p ${OGDB_HOME_1}
    fi

    rm -rf ${OGDB_HOME_1}/add-ons
    rm -rf ${OGDB_HOME_1}/bin
    rm -rf ${OGDB_HOME_1}/lib
    rm -rf ${OGDB_HOME_1}/admin

    # tar -zxvf ${code_path}/output/bin/oGRAC-DATABASE-LINUX-64bit/oGRAC-RUN-LINUX-64bit.tar.gz -C ${OGDB_HOME_1}
    # cp -rf ${OGDB_HOME_1}/oGRAC-RUN-LINUX-64bit/add-ons     ${OGDB_HOME_1}
    # cp -rf ${OGDB_HOME_1}/oGRAC-RUN-LINUX-64bit/bin         ${OGDB_HOME_1}
    # cp -rf ${OGDB_HOME_1}/oGRAC-RUN-LINUX-64bit/lib         ${OGDB_HOME_1}
    # cp -rf ${OGDB_HOME_1}/oGRAC-RUN-LINUX-64bit/admin       ${OGDB_HOME_1}
    # cp -rf ${OGDB_HOME_1}/oGRAC-RUN-LINUX-64bit/package.xml ${OGDB_HOME_1}
    # rm -rf ${OGDB_HOME_1}/oGRAC-RUN-LINUX-64bit

    cp_ograc_add_ons /home/ogracdb1/install
    cp_ograc_bin /home/ogracdb1/install
    cp_ograc_lib /home/ogracdb1/install
    cp -R ${code_path}/pkg/admin  ${OGDB_HOME_1}/

    chmod -R 777 ${OGDB_HOME}/
    chown -R ogracdba:ogracdba ${OGDB_HOME}/
    chmod -R 777 ${OGDB_HOME_1}/
    chown -R ogracdba:ogracdba ${OGDB_HOME_1}/

    echo "copy linux lib complate!!"   
    echo "start to init cms 1"   
    init_and_start_cms1

    echo "Start ogracd with nomount:"

	echo export CMS_HOME=${OGDB_HOME} >> /home/ogracdba/.bashrc
    nohup su - ogracdba -c 'ogracd nomount -D ${OGDB_HOME}' >> $report_file  2>&1 &
    pid=`ps ux | grep ogracd |grep -v grep |awk '{print $2}'`
    echo "ogracd pid=$pid"
    sleep 10
    rm -rf /home/ogsql.log
    echo "create database ..."
    chmod -R 777 ${code_path}/CI/build/script/init.sql
    chown -R ogracdba:ogracdba ${code_path}/CI/build/script/init.sql
    su - ogracdba -c "ogsql sys/sys@127.0.0.1:1611 -q -f ${code_path}/CI/build/script/init.sql" >> /home/ogsql.log

    echo "start ogracd node1"
    sleep 60

    echo export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:${OGDB_HOME_1}/add-ons/nomlnx:${OGDB_HOME_1}/add-ons:${OGDB_HOME_1}/lib >> /home/ogracdba/.bashrc
    echo export PATH=${OGDB_HOME_1}/bin:$PATH >> /home/ogracdba/.bashrc
    echo "start to init cms 2"   
    init_and_start_cms2
    export CMS_HOME=${OGDB_HOME_1}

    echo export CMS_HOME=${OGDB_HOME_1} >> /home/ogracdba/.bashrc
    su - ogracdba -c 'ogracd -h' 2>&1
    su - ogracdba -c 'ogracd -v' 2>&1
    nohup su - ogracdba -c 'ogracd -D ${OGDB_HOME_1}' >> $report_file  2>&1 &
    sleep 20  
    pid1=`ps ux | grep ogracd |grep -v grep |awk '{print $2}'`
    echo "ogracd pid1=$pid1"
	sleep 10

	echo "create new user"
   
    su - ogracdba -c 'ogsql sys/sys@127.0.0.1:1611 -c "create user cluster_tester identified by database_123;" ' >> /home/ogsql.log
   
    su - ogracdba -c 'ogsql sys/sys@127.0.0.1:1611 -c "grant dba to cluster_tester;" ' >> /home/ogsql.log

    su - ogracdba -c 'ogsql sys/sys@127.0.0.1:1611 -c "grant all privileges to cluster_tester;" ' >> /home/ogsql.log

    su - ogracdba -c 'ogsql sys/sys@127.0.0.1:1611 -c "grant unlimited tablespace to cluster_tester;" ' >> /home/ogsql.log

    error_num=`cat /home/ogsql.log |grep 'Succeed.'|wc -l`
    if [ $error_num -eq 0 ];then
       echo "Error: create database failed"
       collect_core
       exit 1
    fi
	sleep 2
    echo "copy linux lib complate!!"

}

run_ogbox_test()
{
    su - ogracdba -c "ogbox -T cminer -c ${code_path}/ogbox_test/ctrl_test -F -D -C"
    su - ogracdba -c "ogbox -T cminer -f ${code_path}/ogbox_test/page_test -F -D -C"
    su - ogracdba -c "ogbox -T cminer -l ${code_path}/ogbox_test/redo_test -F -D -C"
    su - ogracdba -c "echo -e 'y' | ogbox -T crepair -k ${code_path}/ogbox_test/dataObj -c storage.redo[1].logfiles[9].block_size=5120" || true
    echo
    su - ogracdba -c "echo -e 'y' | ogbox -T crepair -k ${code_path}/ogbox_test/dataObj -c storage.node[0].rcy_point=0-0-0-0-0" || true
    echo
    su - ogracdba -c "echo -e 'y' | ogbox -T crepair -k ${code_path}/ogbox_test/dataObj -c storage.node[1].lrp_point=0-0-0-0-0" || true
    echo
    su - ogracdba -c "echo -e 'y' | ogbox -T crepair -k ${code_path}/ogbox_test/dataObj -c storage.spaces[9].spaceid=1" || true
    echo
    su - ogracdba -c "echo -e 'y' | ogbox -T crepair -k ${code_path}/ogbox_test/dataObj -c storage.datafiles[9].dfileid=1" || true
    echo
    su - ogracdba -c "echo -e 'y' | ogbox -T crepair -k ${code_path}/ogbox_test/dataObj -c storage.redo[1].archive[9].first=1" || true
    echo
    su - ogracdba -c "echo -e 'y' | ogbox -T crepair -k ${code_path}/ogbox_test/dataObj -c storage.redo[1].logfiles[9].block_size=1" || true
    echo
    su - ogracdba -c "echo -e 'y' | ogbox -T crepair -k ${code_path}/ogbox_test/dataObj -c storage.node[0].raft_point=0" || true
    echo
    su - ogracdba -c "echo -e 'y' | ogbox -T crepair -k ${code_path}/ogbox_test/dataObj -c storage.redo[6].logfiles[9].block_size=1" || true
    echo
    su - ogracdba -c "echo -e 'y' | ogbox -T crepair -k ${code_path}/ogbox_test/dataObj -c storage.redo[1].archive[10250].first=1" || true
    echo
    su - ogracdba -c "echo -e 'y' | ogbox -T crepair -k ${code_path}/ogbox_test/dataObj -c storage.redo[1].logfiles[257].block_size=1" || true
    echo
    su - ogracdba -c "echo -e 'y' | ogbox -T crepair -k ${code_path}/ogbox_test/dataObj -c storage.redo[1].datefiles[257].block_size=1" || true
    echo
    su - ogracdba -c "echo -e 'y' | ogbox -T crepair -k ${code_path}/ogbox_test/dataObj -c storage.node[6].rcy_point=0-0-0-0-0" || true
    echo
    su - ogracdba -c "echo -e 'y' | ogbox -T crepair -k ${code_path}/ogbox_test/dataObj -c storage.spaces[1025].spaceid=1" || true
    echo
    su - ogracdba -c "echo -e 'y' | ogbox -T crepair -k ${code_path}/ogbox_test/dataObj -c storage.datafiles[1025].dfileid=1" || true
    echo
}

run_cluster_test()
{
	log "========================= Run Cluster Test ======================="
	echo `pwd`
    chown -R ogracdba:ogracdba ${code_path}/output/bin/cluster_test
    chmod -R 777 ${code_path}/output/bin/cluster_test
    # chown -R ogracdba:ogracdba ${code_path}/bazel-bin/pkg/test/cluster_test/cluster_test
    # chmod -R 777 ${code_path}bazel-bin/pkg/test/cluster_test/cluster_test
	# su - ogracdba -c "${code_path}/bazel-bin/pkg/test/cluster_test/cluster_test '127.0.0.1:1611' ${PORT}':1612' $1" 2>&1 | tee -a $report_file
    su - ogracdba -c "${code_path}/output/bin/cluster_test '127.0.0.1:1611' ${PORT}':1612' $1" 2>&1 | tee -a $report_file
    test_num=`cat $report_file | grep '\--------------------- TEST_CASE' | wc -l`
    succ_num=`cat $report_file | grep '\--------------------- FINISHED ---------------------' | wc -l`
    BASHRC_AFTER_NUM=$(sed -n '$=' /home/ogracdba/.bashrc)
	if [ $succ_num -ne $test_num ];then
	   echo "something wrong when cluster_test!"
	   echo "something wrong when cluster_test!" >> $report_file 2>&1
	   collect_core
	   exit 1
	fi
    sed $(($BASHRC_ORIGIN_NUM+1)),${BASHRC_AFTER_NUM}d -i /home/ogracdba/.bashrc
	echo "success finish cluster_test!"
}

gen_lcov_report()
{
    if [[ ! -d "${code_path}/lcov_output" ]]
    then 
	    mkdir -p ${code_path}/lcov_output
    fi
   
    coverage_info_name="${code_path}/lcov_output/cluster_test_coverage.info"
    coverage_report_name="${code_path}/lcov_output/cluster_test_coverage.report"
    find ${code_path}/ -name "*.gcno" | xargs touch
    lcov --capture --directory ${code_path}/ --rc lcov_branch_coverage=1 --output-file "${coverage_info_name}" 
    lcov -l --rc lcov_branch_coverage=1 "${coverage_info_name}" > "${coverage_report_name}" 
    # Reset all execution counts to zero
    lcov -d ./ -z
    log ">>>>>>>>>>>>>>>>>>>>> Lcov report successfully <<<<<<<<<<<<<<<<<<<<<<<<<<<"
}

main()
{
    LCOV_ENABLE=FALSE
    test_list=-1
    for arg in "$@"
    do 
        echo "arg is ${arg}"
        if [ ${arg} = "--coverage" ]
        then 
            echo "Enable coverage detection."
            LCOV_ENABLE=TRUE
        fi

        if [ ${arg} = "test_list_0" ]
        then 
            echo "Enable coverage detection."
            test_list=0
        fi

        if [ ${arg} = "test_list_1" ]
        then 
            echo "Enable coverage detection."
            test_list=1
        fi
    done

    echo "test_list is ${test_list}"

    init_og_regress
    make_code
    install_ogracdb
    #run_ogbox_test
    run_cluster_test ${test_list}

    # collect_core

    if [ "${LCOV_ENABLE}" = TRUE ]
    then 
        gen_lcov_report
    fi
}

main "$@"
