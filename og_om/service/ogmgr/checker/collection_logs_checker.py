# Copyright (c) 2026 Huawei Technologies Co., Ltd.
# oGRAC is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

from log_tool.om_log import TASK_LOG


class LogEnumCheck:

    @staticmethod
    def check(input_params_dict):
        _type = input_params_dict.get('type')
        if _type not in ('recent', 'all'):
            TASK_LOG.error('collection logs fail, type must be recent or all, type is {}'.format(_type))
            return False

        return True
