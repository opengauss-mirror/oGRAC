#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
source "${CURRENT_PATH}"/env.sh
deploy_user=$(python3 ${CURRENT_PATH}/get_config_info.py "deploy_user")

su - "${ograc_user}" -s /bin/bash -c "chown -hR :${ograc_common_group} /mnt/dbdata/local/ograc" > /dev/null 2>&1
su - "${ograc_user}" -s /bin/bash -c "find /mnt/dbdata/local/ograc/tmp/data/dbstor -type d -print0 | xargs -0 chmod 770" > /dev/null 2>&1
su - "${ograc_user}" -s /bin/bash -c "chmod 660 /opt/ograc/log/dbstor/run/*" > /dev/null 2>&1
su - "${ograc_user}" -s /bin/bash -c "chmod 660 /mnt/dbdata/local/ograc/tmp/data/log/ogracstatus.log" > /dev/null 2>&1

su - "${ograc_user}" -s /bin/bash -c "chown -hR :${ograc_common_group} /opt/ograc/cms/dbstor" > /dev/null 2>&1
su - "${ograc_user}" -s /bin/bash -c "find /opt/ograc/ -type d -print0 | xargs -0 chmod 770" > /dev/null 2>&1
su - "${ograc_user}" -s /bin/bash -c "find /opt/ograc/log -type d -print0 | xargs -0 chmod -R 770" > /dev/null 2>&1

su - "${ograc_user}" -s /bin/bash -c "chmod 640 /opt/ograc/cms/dbstor/data/logs/run/*" > /dev/null 2>&1
su - "${ograc_user}" -s /bin/bash -c "find /opt/ograc/log/ograc -type f -print0 | xargs -0 chmod 660" > /dev/null 2>&1
su - "${ograc_user}" -s /bin/bash -c "find /opt/ograc/log/cms -type f -print0 | xargs -0 chmod 660" > /dev/null 2>&1
su - "${ograc_user}" -s /bin/bash -c "find /opt/ograc/log/og_om -type f -print0 | xargs -0 chmod 660" > /dev/null 2>&1
su - "${ograc_user}" -s /bin/bash -c "find /opt/ograc/log/deploy -type f -print0 | xargs -0 chmod 660" > /dev/null 2>&1
su - "${ograc_user}" -s /bin/bash -c "find /opt/ograc/log/ograc_exporter -type f -print0 | xargs -0 chmod 660" > /dev/null 2>&1
su - "${ograc_user}" -s /bin/bash -c "find /opt/ograc/log/dbstor -type f -print0 | xargs -0 chmod 660" > /dev/null 2>&1

su - "${ograc_user}" -s /bin/bash -c "chgrp -R ${ograc_common_group} /mnt/dbdata/local/ograc/tmp/data/log/ogracstatus.log" > /dev/null 2>&1
su - "${ograc_user}" -s /bin/bash -c "chgrp -R ${ograc_common_group} /opt/ograc/log" > /dev/null 2>&1
su - "${ograc_user}" -s /bin/bash -c "chown -R :${ograc_common_group} /opt/ograc/log" > /dev/null 2>&1
su - "${ograc_user}" -s /bin/bash -c "chown -R :${ograc_common_group} /opt/ograc/dbstor/" > /dev/null 2>&1
su - "${ograc_user}" -s /bin/bash -c "chown -R :${ograc_common_group} /opt/ograc/ograc/" > /dev/null 2>&1
su - "${ograc_user}" -s /bin/bash -c "chown -R :${ograc_common_group} /opt/ograc/cms/" > /dev/null 2>&1


