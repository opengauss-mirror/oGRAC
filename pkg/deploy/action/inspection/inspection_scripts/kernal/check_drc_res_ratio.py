#!/usr/bin/env python3
import json
import os
import sys

_CUR_DIR = os.path.dirname(os.path.abspath(__file__))
_INSPECTION_DIR = os.path.abspath(os.path.join(_CUR_DIR, "../.."))
sys.path.insert(0, _INSPECTION_DIR)
sys.path.insert(0, _CUR_DIR)

from ograc_check import CheckContext
from ograc_check import BaseItem
from ograc_check import ResultStatus
from log_tool import setup

class CheckDRCResRatio(BaseItem):
    '''
    check DRC res ratio
    '''
    def __init__(self):
        super(CheckDRCResRatio, self).__init__(self.__class__.__name__)
        self.suggestion = "If DRC resource ratio is too high, try checkpoint"
        self.standard = "Check DRC res ratio, check if ratio is too high."
        self.title = "Check for DRC res ratio"
        self.epv = 0.9375

    def do_check(self):
        '''
        function : Check for DRC res ratio
        input : NA
        output : NA
        '''
        self.result.epv = self.epv
        self.result.rst = ResultStatus.OK

        sql = "SELECT RATIO FROM DV_DRC_RES_RATIO;"
        self.result.raw = sql.replace("\$", "$")

        res_ratio_dict = {}
        status, records = self.get_sql_result(sql)

        if (status == 0):
            res_ratio_dict['PAGE_BUF'] = records["records"][0][0]
            res_ratio_dict['GLOBAL_LOCK'] = records["records"][1][0]
            res_ratio_dict['LOCAL_LOCK'] = records["records"][2][0]
            res_ratio_dict['LOCAL_TXN'] = records["records"][3][0]
            res_ratio_dict['GLOBAL_TXN'] = records["records"][4][0]
            res_ratio_dict['LOCK_ITEM'] = records["records"][5][0]
            self.result.rst = ResultStatus.OK
            for value in res_ratio_dict.values():
                if (float(value) >= self.result.epv) :
                    self.result.rst = ResultStatus.NG
        else:
            self.result.rst = ResultStatus.ERROR
            res_ratio_dict["except"] = records

        self.result.val = json.dumps(res_ratio_dict)


if __name__ == '__main__':
    '''
    main
    '''
    ograc_log = setup('ograc')
    if(os.getuid() == 0):
        ograc_log.error("Cannot use root user for this operation!")
        sys.exit(1)

    checker = CheckDRCResRatio()
    checker_context = CheckContext()
    db_user = input()
    db_pass = input()
    checker_context.db_user = db_user
    checker_context.db_passwd = db_pass
    context_attr = ["db_addr", "port"]
    item_index = 0
    for argv in sys.argv[1:]:
        setattr(checker_context, context_attr[item_index], argv)
        item_index += 1
    checker.run_check(checker_context, ograc_log)
