# Copyright (c) 2026 Huawei Technologies Co., Ltd.
# oGRAC is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

from pathlib import Path

from task_obj import TASK
from log_tool.om_log import LOGGER, LOG
from log_tool.om_log import TASK_LOG
from common.output_tool import CommonResult
from common.common_tool import TimeTool
from log_tool.om_log import TASK_LOG

LOG_FILE_PATH = str(Path(LOG.handlers[0].baseFilename))
SUCCESS = 'success'


class QueryLogTask(TASK):

    def __init__(self, task_name, handler, params_check_dict):
        super().__init__(task_name, handler, params_check_dict)

    def task_execute(self, input_params, task_logger: LOGGER):
        task_logger.set_finish_time(TimeTool.get_current_time())
        task_logger.info(self.task_name, SUCCESS)
        TASK_LOG.info('doing log queryn, path is: {}'.format(LOG_FILE_PATH))
        return CommonResult(output_data=LOG_FILE_PATH)


if __name__ == '__main__':
    lt = QueryLogTask(None, None)
    lg = LOGGER(None, None, None)
    lt.task_execute({}, lg)
