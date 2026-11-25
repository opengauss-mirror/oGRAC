# Copyright (c) 2026 Huawei Technologies Co., Ltd.
# oGRAC is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

CONSOLE_CONF = {
    "log": {
        "use_syslog": False,
        "debug": False,
        "log_dir": "/opt/ograc/log/og_om",
        "log_file_max_size": 1048576,
        "log_file_backup_count": 5,
        "log_date_format": "%Y-%m-%d %H:%M:%S",
        "logging_default_format_string": "%(asctime)s console %(levelname)s [pid:%(process)d] [%(threadName)s] "
                                         "[tid:%(thread)d] [%(filename)s:%(lineno)d %(funcName)s] %(message)s",
        "logging_context_format_string": "%(asctime)s console %(levelname)s [pid:%(process)d] [%(threadName)s] "
                                         "[tid:%(thread)d] [%(filename)s:%(lineno)d %(funcName)s] %(message)s"
    }
}
