#!/bin/bash
# Copyright Huawei Technologies Co., Ltd. 2010-2018. All rights reserved.
# This script is used for compiling code via CMake and making packages
set -e

func_prepare_git_msg()
{
  echo "start func_prepare_git_msg"
  git_id=$(git rev-parse --short HEAD)
  WHOLE_COMMIT_ID=$(git rev-parse HEAD)
  merge_time=$(git log | grep Date | sed -n '1p' | sed 's/^Date:\s*//g')
  oGRAC_merge_time=$(git log | grep Date | sed -n '1p' | sed 's/^Date:\s*//g')
  driver_commit_id=$(git log --pretty=format:%h -n 1 ${OGRACDB_SRC}/driver/)
  ogsql_commit_id=$(git log --pretty=format:%h -n 1 ${OGRACDB_SRC}/utils/ogsql)
  cat /dev/null > ${OGRACDB_BUILD}/conf/git_message.in
  echo "git_id=${git_id}" >> ${OGRACDB_BUILD}/conf/git_message.in
  echo "gitVersion=${WHOLE_COMMIT_ID}" >> ${OGRACDB_BUILD}/conf/git_message.in
  echo "merge_time=${merge_time}" >> ${OGRACDB_BUILD}/conf/git_message.in
  echo "oGRAC_merge_time=${oGRAC_merge_time}" >> ${OGRACDB_BUILD}/conf/git_message.in
  echo "driver_commit_id=${driver_commit_id}" >> ${OGRACDB_BUILD}/conf/git_message.in
  echo "ogsql_commit_id=${ogsql_commit_id}" >> ${OGRACDB_BUILD}/conf/git_message.in
}