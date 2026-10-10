#!/bin/bash
# Copyright Huawei Technologies Co., Ltd. 2010-2018. All rights reserved.
# This script is used for compiling code via CMake and making packages
set -e

# Component packages use canonical Linux names; the outer package carries the OS name.
declare PACKAGE_OS_SUFFIX="LINUX"

func_get_package_dir_name()
{
  local package_type="$1"
  local package_prefix="${2:-}"
  local config_in_file="${OGRACDB_BUILD}/include/config.h"

  if [[ -z "${package_type}" ]]; then
    echo "package type is required" >&2
    return 1
  fi

  if [[ -z "${package_prefix}" ]]; then
    if [[ ! -f "${config_in_file}" ]]; then
      echo "config file not exist: ${config_in_file}" >&2
      return 1
    fi
    package_prefix=$(awk '$1 == "#define" && $2 == "PACK_PREFIX" { print $3; exit }' "${config_in_file}")
  fi

  if [[ -z "${package_prefix}" ]]; then
    echo "PACK_PREFIX not found in ${config_in_file}" >&2
    return 1
  fi

  printf '%s-%s-%s-%sbit' "${package_prefix}" "${package_type}" "${PACKAGE_OS_SUFFIX}" "${ARCH:-$(getconf LONG_BIT)}"
}

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
