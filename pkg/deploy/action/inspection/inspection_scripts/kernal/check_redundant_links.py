#!/usr/bin/env python3
# Copyright (c) 2026 Huawei Technologies Co., Ltd.
# oGRAC is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

import json
import os
import sys

_CUR_DIR = os.path.dirname(os.path.abspath(__file__))
_INSPECTION_DIR = os.path.abspath(os.path.join(_CUR_DIR, "../.."))
sys.path.insert(0, _INSPECTION_DIR)
sys.path.insert(0, _CUR_DIR)

from config import get_config
from ograc_check import CheckContext
from ograc_check import BaseItem
from ograc_check import ResultStatus
from log_tool import setup

_cfg = get_config()
_paths = _cfg.paths


class CheckRedundantLinks(BaseItem):
    '''
    check version of database
    '''
    def __init__(self):
        super(CheckRedundantLinks, self).__init__(self.__class__.__name__)
        self.title = "Check redundant links"

    def do_check(self):
        '''
        function : Check redundant links
        input : NA
        output : NA
        '''

        vals = {}
        self.result.rst = ResultStatus.OK

        cmd = "python3 %s" % _paths.check_link_script
        self.result.raw = cmd
        status, output = self.get_cmd_result(cmd, self.user)
        if (status == 0):
            vals["success"] = "Have redundant link."
        else:
            self.result.rst = ResultStatus.ERROR
            vals["except"] = "Do not have redundant link, for details, see the %s ." % _paths.dbstor_cgwshowdev_log

        self.result.val = json.dumps(vals)


if __name__ == '__main__':
    '''
    main
    '''
    ograc_log = setup('ograc')
    if(os.getuid() == 0):
        ograc_log.error("Cannot use root user for this operation!")
        sys.exit(1)

    checker = CheckRedundantLinks()
    checker_context = CheckContext()
    checker.run_check(checker_context, ograc_log)
