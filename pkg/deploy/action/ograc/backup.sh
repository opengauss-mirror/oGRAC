# 确定相对路径
set +x
#当前路径
CURRENT_PATH=$(dirname $(readlink -f $0))

OGRAC_INSTALL_LOG_FILE=/opt/ograc/log/ograc/ograc_deploy.log
OGRAC_INSTALL_CONFIG=/opt/ograc/ograc/cfg

function log() {
  printf "[%s] %s\n" "`date -d today \"+%Y-%m-%d %H:%M:%S\"`" "$1" >> ${OGRAC_INSTALL_LOG_FILE}
}

# 判断是否存在对应的文件，不存在返回报错，存在则继续运行
function ograc_backup()
{
    if [ ! -d /opt/ograc/backup/files/ograc ]; then
        mkdir -p -m 700 /opt/ograc/backup/files/ograc
    fi

    if [ -f /mnt/dbdata/local/ograc/tmp/data/dbstor/conf/dbs/dbstor_config.ini ]; then
        cp -af /mnt/dbdata/local/ograc/tmp/data/dbstor/conf/dbs/dbstor_config.ini /opt/ograc/backup/files/ograc/
    fi

    if [ -f /mnt/dbdata/local/ograc/tmp/data/cfg/ogracd.ini ]; then
        cp -af /mnt/dbdata/local/ograc/tmp/data/cfg/ogracd.ini /opt/ograc/backup/files/ograc/
    fi

    if [ -f /mnt/dbdata/local/ograc/tmp/data/cfg/ogsql.ini ]; then
        cp -af /mnt/dbdata/local/ograc/tmp/data/cfg/ogsql.ini /opt/ograc/backup/files/ograc/
    fi

    if [ -d /mnt/dbdata/local/ograc/tmp/data/cfg ]; then
        cp -ar /mnt/dbdata/local/ograc/tmp/data/cfg /opt/ograc/backup/files/ograc/
    fi

    if [ -f ${OGRAC_INSTALL_CONFIG}/ograc_config.json ]; then
        cp -af ${OGRAC_INSTALL_CONFIG}/ograc_config.json /opt/ograc/backup/files/ograc/
    fi
  
    log "ograc back up success."
    return 0
}

ograc_backup