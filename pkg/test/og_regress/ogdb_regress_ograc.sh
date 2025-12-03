#!/bin/bash

install_dir=$1
sys_passwd=$2
og_schedule_list=$3

ogsql=${install_dir}/bin/ogsql

rm -rf ./results/*
rm -rf ${install_dir}/cumu_*.bak*
rm -rf ${install_dir}/ogracdb_*.bak*
export OGSQL_SSL_QUIET=TRUE
./og_regress --bindir=${ogsql} --user=sys/${sys_passwd} --host=127.0.0.1 --port=1611 --inputdir=./sql/ --outputdir=./results/ --expectdir=./expected/ --schedule=./${og_schedule_list}
if [ $? -eq 0 ];then
   echo "    og_regress        :  OK"
   echo "********************* END: og_regress *********************"
else
   echo "    og_regress        :  FAILED"
   echo "********************* END: og_regress *********************"
fi
