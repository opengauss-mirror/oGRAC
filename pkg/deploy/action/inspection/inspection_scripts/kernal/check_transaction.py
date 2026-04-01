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

MAX_MICRO_TIME = 3 * 60 * 1000000


class CheckTransaction(BaseItem):
    '''
    check transaction of database
    '''
    def __init__(self):
        super(CheckTransaction, self).__init__(self.__class__.__name__)
        self.suggestion = \
            "Configurable time, if there is a long transaction, \
it is recommended that the user modify the SQL statement."
        self.standard = "Check transactions greater than 3 minutes, check if they do not exist."
        self.title = "check for long time transactions"
        self.epv = 0

    def do_check(self):
        '''
        function : Check for transaction of long time
        input : NA
        output : NA
        '''

        vals = {}
        self.result.epv = self.epv
        self.result.rst = ResultStatus.OK

        if self.copyright:
            sql = "SELECT COUNT(1) FROM DV_TRANSACTIONS WHERE STATUS = 'ACTIVE'"
            sql += " AND EXEC_TIME > %d;" % MAX_MICRO_TIME
        else:
            sql = "SELECT COUNT(1) FROM V\$TRANSACTIONS WHERE STATUS = 'ACTIVE'"
            sql += " AND EXEC_TIME > %d;" % MAX_MICRO_TIME
        self.result.raw = sql.replace("\$", "$")

        status, records = self.get_sql_result(sql)
        if (status == 0):
            count = records["records"][0][0]
            if int(count) == self.result.epv:
                self.result.rst = ResultStatus.OK
            else:
                self.result.rst = ResultStatus.NG
            vals["transaction"] = count
        else:
            self.result.rst = ResultStatus.ERROR
            vals["except"] = records

        self.result.val = json.dumps(vals)



if __name__ == '__main__':
    '''
    main
    '''
    ograc_log = setup('ograc')
    if(os.getuid() == 0):
        ograc_log.error("Cannot use root user for this operation!")
        sys.exit(1)

    checker = CheckTransaction()
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
