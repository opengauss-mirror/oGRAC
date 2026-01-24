#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)
uninstall_type=$1
force_type=$2
auto_create_fs=$2
source ${CURRENT_PATH}/env.sh
source ${CURRENT_PATH}/log4sh.sh

deploy_user=$(python3 ${CURRENT_PATH}/get_config_info.py "deploy_user")
deploy_group=$(python3 ${CURRENT_PATH}/get_config_info.py "deploy_group")
ograc_in_container=$(python3 ${CURRENT_PATH}/get_config_info.py "ograc_in_container")

# 获取已创建路径的路径名
storage_dbstor_fs=$(python3 ${CURRENT_PATH}/get_config_info.py "storage_dbstor_fs")
storage_share_fs=$(python3 ${CURRENT_PATH}/get_config_info.py "storage_share_fs")
storage_archive_fs=$(python3 ${CURRENT_PATH}/get_config_info.py "storage_archive_fs")
storage_metadata_fs=$(python3 ${CURRENT_PATH}/get_config_info.py "storage_metadata_fs")
node_id=$(python3 ${CURRENT_PATH}/get_config_info.py "node_id")
deploy_mode=$(python3 ${CURRENT_PATH}/get_config_info.py "deploy_mode")

function clear_residual_files() {
    # 滚动升级场景，卸载是需要删除当前目录
    if [ -d /mnt/dbdata/remote/metadata_"${storage_metadata_fs}"/upgrade ];then
        rm -rf /mnt/dbdata/remote/metadata_"${storage_metadata_fs}"/upgrade
    fi
    if [ -f /opt/backup_note ];then
        rm -rf /opt/backup_note
    fi
    if [ -f /mnt/dbdata/remote/metadata_"${storage_metadata_fs}"/upgrade.lock ];then
        rm -rf /mnt/dbdata/remote/metadata_"${storage_metadata_fs}"/upgrade.lock
    fi
    if [[ -f /mnt/dbdata/remote/metadata_"${storage_metadata_fs}"/deploy_param.json ]] && [[ "${node_id}" == "0" ]];then
        rm -rf /mnt/dbdata/remote/metadata_"${storage_metadata_fs}"/deploy_param.json
    fi

    if [[ -f /mnt/dbdata/remote/metadata_"${storage_metadata_fs}"/dr_deploy_param.json ]] && [[ "${node_id}" == "0" ]];then
        rm -rf /mnt/dbdata/remote/metadata_"${storage_metadata_fs}"/dr_deploy_param.json
    fi

    if [[ -f /mnt/dbdata/remote/metadata_"${storage_metadata_fs}"/versions.yml ]] && [[ "${node_id}" == "0" ]]; then
        rm -rf /mnt/dbdata/remote/metadata_"${storage_metadata_fs}"/versions.yml
    fi

    if [[ "${deploy_mode}" == "dbstor" ]];then
        su -s /bin/bash - "${ograc_user}" -c "dbstor --delete-file --fs-name=${storage_share_fs} --file-name=upgrade" > /dev/null 2>&1
        su -s /bin/bash - "${ograc_user}" -c "dbstor --delete-file --fs-name=${storage_share_fs} --file-name=versions.yml" > /dev/null 2>&1
        su -s /bin/bash - "${ograc_user}" -c "dbstor --delete-file --fs-name=${storage_share_fs} --file-name=dr_deploy_param.json" > /dev/null 2>&1
    fi
}

# 为支持卸载重入，增加创建用户
function initUserAndGroup()
{
    # 创建用户组
    groupadd ogracgroup -g 1100 > /dev/null 2>&1
    useradd ograc -s /sbin/nologin -u 6000 > /dev/null 2>&1
    useradd ogmgruser -s /sbin/nologin -u 6004 > /dev/null 2>&1
    # 增加用户到用户组
    usermod -a -G ogracgroup ${deploy_user}
    usermod -a -G ogracgroup ograc
    usermod -a -G ogracgroup ogmgruser
    usermod -a -G ${deploy_group} ograc
}

function uninstall_rpm()
{
    RPM_PACK_ORG_PATH="/opt/ograc/image/oGRAC-RUN-CENTOS-64bit"
    result=`rpm -qa ograc | wc -l`
    if [ ${result} -ne 0 ]; then
        rpm -ev ograc --nodeps
    fi

    if [ -d ${RPM_PACK_ORG_PATH} ]; then
        rm -rf ${RPM_PACK_ORG_PATH}
    fi
}

# 根据性能要求配置/etc/security/limits.conf，进程内线程优先级提升开关
function clear_security_limits() {
  local security_limits=/etc/security/limits.conf
  grep "${ograc_user} hard nice -20" "${security_limits}"
  if [ $? -eq 0 ];then
    sed -i "/${ograc_user} hard nice -20/ d"  "${security_limits}"
  fi
  grep "${ograc_user} soft nice -20" "${security_limits}"
  if [ $? -eq 0 ];then
    sed -i "/${ograc_user} soft nice -20/ d" "${security_limits}"
  fi
  grep "${ograc_user} hard nice -20" "${security_limits}" || grep "${ograc_user} soft nice -20" "${security_limits}"
  if [ $? -eq 0 ];then
    logAndEchoInfo "clear security limits failed"
    exit 1
  fi
  logAndEchoInfo "clear security limits success"
}

# override模式下umount
function umount_fs() {
    if [[ "$ograc_in_container" != "0" ]]; then
        return 0
    fi

    if [[ ${storage_archive_fs} != '' ]] && [[ -d /mnt/dbdata/remote/archive_"${storage_archive_fs}"/binlog ]] && [[ "${node_id}" == "0" ]]; then
      rm -rf /mnt/dbdata/remote/archive_"${storage_archive_fs}"/binlog
    fi
    if [[ ${storage_archive_fs} != '' ]] && [[ -d /mnt/dbdata/remote/archive_"${storage_archive_fs}"/logicrep_conf ]] && [[ "${node_id}" == "0" ]]; then
      rm -rf /mnt/dbdata/remote/archive_"${storage_archive_fs}"/logicrep_conf
    fi
    rm -rf /mnt/dbdata/remote/share_"${storage_share_fs}"/node"${node_id}"_install_record.json > /dev/null 2>&1

    sysctl fs.nfs.nfs_callback_tcpport=0
    # 取消nfs挂载
    umount -f -l /mnt/dbdata/remote/share_${storage_share_fs} > /dev/null 2>&1
    umount -f -l /mnt/dbdata/remote/archive_${storage_archive_fs} > /dev/null 2>&1
    umount -f -l /mnt/dbdata/remote/metadata_${storage_metadata_fs} > /dev/null 2>&1
    umount -f -l /mnt/dbdata/remote/storage_${storage_dbstor_fs} > /dev/null 2>&1

    rm -rf /mnt/dbdata/remote/archive_${storage_archive_fs} > /dev/null 2>&1
    rm -rf /mnt/dbdata/remote/storage_${storage_dbstor_fs}/data > /dev/null 2>&1
    rm -rf /mnt/dbdata/remote/share_${storage_share_fs} > /dev/null 2>&1
    rm -rf /mnt/dbdata/remote/metadata_${storage_metadata_fs} > /dev/null 2>&1
}


# 检查输入项是否为override或者reserve
if [[ ${uninstall_type} != 'override' && ${uninstall_type} != 'reserve' ]]; then
    logAndEchoInfo "uninstall_type must be override or reserve"
    exit 1
fi

if [ ! -f ${CURRENT_PATH}/../config/deploy_param.json ]; then
    logAndEchoInfo "ograc id not install, uninstall success."
    exit 0
fi

initUserAndGroup

python3 ${CURRENT_PATH}/write_config.py "uninstall_type" ${uninstall_type}

logAndEchoInfo "uninstall begin"

clear_security_limits

# 清理残留文件
clear_residual_files

logAndEchoInfo "Begin to uninstall. [Line:${LINENO}, File:${SCRIPT_NAME}]"
for lib_name in "${UNINSTALL_ORDER[@]}"
do
    logAndEchoInfo "uninstall ${lib_name} . [Line:${LINENO}, File:${SCRIPT_NAME}]"
    if [[ ${uninstall_type} == 'override' && ${force_type} == 'force' ]]; then
        sh ${CURRENT_PATH}/${lib_name}/appctl.sh uninstall ${uninstall_type} ${force_type} >> ${OM_DEPLOY_LOG_FILE} 2>&1
        if [ $? -eq 0 ]; then
            logAndEchoInfo "force uninstall ${lib_name} result is success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        else
            logAndEchoError "force uninstall ${lib_name} result is failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            logAndEchoError "For details, see the /opt/ograc/log/${lib_name}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            exit 1
        fi
    else
        sh ${CURRENT_PATH}/${lib_name}/appctl.sh uninstall ${uninstall_type} >> ${OM_DEPLOY_LOG_FILE} 2>&1
        if [ $? -eq 0 ]; then
            logAndEchoInfo "uninstall ${lib_name} result is success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        else
            logAndEchoError "uninstall ${lib_name} result is failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            logAndEchoError "For details, see the /opt/ograc/log/${lib_name}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            exit 1
        fi
    fi
done

if [ ! -f /opt/ograc/installed_by_rpm ]; then
    uninstall_rpm
fi

# 如果uninstall_type为override 执行以下操作
echo "uninstall_type is: ${uninstall_type}"
if [[ ${uninstall_type} = 'override' ]]; then
  umount_fs

  # 删除创建的公共目录（挂载目录）
  rm -rf /opt/ograc/common/data
  rm -rf /opt/ograc/common/socket
  rm -rf /opt/ograc/common/config

  if [[ ${auto_create_fs} == "delete_fs" && ${node_id} == "0" ]];then
        read -p "please input DM login ip:" dm_login_ip
        if [[ x"${dm_login_ip}" == x"" ]];then
          logAndEchoError "Enter a correct IP address, not None"
          exit 1
        fi

        read -s -p "please input DM login user:" dm_login_user
        if [[ x"${dm_login_user}" == x"" ]];then
          logAndEchoError "Enter a correct user, not None."
          exit 1
        fi
        echo "please input DM login user:${dm_login_user}"

        read -s -p "please input DM login passwd:" dm_login_pwd
        if [[ x"${dm_login_pwd}" == x"" ]];then
          logAndEchoError "Enter a correct passwd, not None."
          exit 1
        fi
        echo ""
        logAndEchoInfo "Auto delete fs"
        echo -e "${dm_login_user}\n${dm_login_pwd}" | python3 -B "${CURRENT_PATH}"/storage_operate/create_file_system.py --action="delete" --ip="${dm_login_ip}"
        if [ $? -ne 0 ];then
            logAndEchoError "Auto delete fs failed, for details see the /opt/ograc/log/deploy/om_deploy/create_fs_log.log"
            exit 1
        fi
        logAndEchoInfo "Auto delete fs success"
  fi

  if [ -f /opt/ograc/installed_by_rpm ]; then
    find /usr/lib64 -maxdepth 1 -name 'libog*' -user ograc -type f -delete
  fi

  # 删除已创建用户
  if id -u ograc > /dev/null 2>&1; then
      userdel -rf ograc
      if [ $? -eq 0 ]; then
          logAndEchoInfo "remove user ograc success"
      else
          logAndEchoError "remove user ograc failed"
          exit 1
      fi
  fi

  if id -u cantainduser > /dev/null 2>&1; then
      userdel -rf cantainduser
      if [ $? -eq 0 ]; then
          logAndEchoInfo "remove user cantainduser success"
      else
          logAndEchoError "remove user cantainduser failed"
          exit 1
      fi
  fi

  if id -u cmsuser > /dev/null 2>&1; then
      userdel -rf cmsuser
      if [ $? -eq 0 ]; then
          logAndEchoInfo "remove user cmsuser success"
      else
          logAndEchoError "remove user cmsuser failed"
          exit 1
      fi
  fi

  if id -u ogmgruser > /dev/null 2>&1; then
      userdel -rf ogmgruser
      if [ $? -eq 0 ]; then
          logAndEchoInfo "remove user ogmgruser success"
      else
          logAndEchoError "remove user ogmgruser failed"
          exit 1
      fi
  fi

  if id -u ogcliuser > /dev/null 2>&1; then
      userdel -rf ogcliuser
      if [ $? -eq 0 ]; then
          logAndEchoInfo "remove user ogcliuser success"
      else
          logAndEchoError "remove user ogcliuser failed"
          exit 1
      fi
  fi

  # 从用户组移除用户
  groups ${deploy_user} | grep "^ogracgroup$"
  if [ $? -eq 0 ]; then
      gpasswd -d ${deploy_user} ogracgroup > /dev/null 2>&1
      if [ $? -eq 0 ]; then
          logAndEchoInfo "remove user ${deploy_user} from ogracgroup success"
      else
          logAndEchoError "remove user ${deploy_user} from ogracgroup failed"
          exit 1
      fi
  fi

  # 删除用户组
  less /etc/group | grep "^ogracgroup" > /dev/null 2>&1
  if [ $? -eq 0 ]; then
      groupdel -f ogracgroup
      if [ $? -eq 0 ]; then
          logAndEchoInfo "remove group ogracgroup success"
      else
          logAndEchoError "remove group ogracgroup failed"
          exit 1
      fi
  fi

  less /etc/group | grep "^ogracmgrgroup" > /dev/null 2>&1
  if [ $? -eq 0 ]; then
      groupdel -f ogracmgrgroup
      if [ $? -eq 0 ]; then
          logAndEchoInfo "remove group ogracmgrgroup success"
      else
          logAndEchoError "remove group ogracmgrgroup failed"
          exit 1
      fi
  fi

  less /etc/group | grep "^ogracctdgroup:" > /dev/null 2>&1
  if [ $? -eq 0 ]; then
      groupdel -f ogracctdgroup
      if [ $? -eq 0 ]; then
          logAndEchoInfo "remove group ogracctdgroup success"
      else
          logAndEchoError "remove group ogracctdgroup failed"
          exit 1
      fi
  fi

  less /etc/group | grep "^ograccmsgroup:" > /dev/null 2>&1
  if [ $? -eq 0 ]; then
      groupdel -f ograccmsgroup
      if [ $? -eq 0 ]; then
          logAndEchoInfo "remove group ograccmsgroup success"
      else
          logAndEchoError "remove group ograccmsgroup failed"
          exit 1
      fi
  fi
  if [ -f /etc/uid_list ];then
      sed -i '/6004/d' /etc/uid_list
      sed -i '/6000/d' /etc/uid_list
  fi

  rm -f /etc/systemd/system/ograc.timer /etc/systemd/system/ograc.service
  rm -f /etc/systemd/system/ograc_logs_handler.timer /etc/systemd/system/ograc_logs_handler.service
  if [ ! -f /opt/ograc/installed_by_rpm ]; then
    rm -rf /opt/ograc/image /opt/ograc/action /opt/ograc/config
  fi
  rm -rf /usr/local/bin/show
fi

logAndEchoInfo "uninstall finished"
exit 0
