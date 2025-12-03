#!/usr/bin/env python
# coding: UTF-8
import json
import os
import sys
from og_check import CheckContext
from og_check import BaseItem
from og_check import ResultStatus
sys.path.append('/opt/ograc/action/inspection')
from log_tool import setup

# minutes converted to microseconds
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

        # Check transactions greater than 3 minutes, check if they do not exist
        if self.copyright:
            sql = "SELECT COUNT(1) FROM DV_TRANSACTIONS WHERE STATUS = 'ACTIVE'"
            sql += " AND EXEC_TIME > %d;" % MAX_MICRO_TIME
        else:
            sql = "SELECT COUNT(1) FROM V\$TRANSACTIONS WHERE STATUS = 'ACTIVE'"
            sql += " AND EXEC_TIME > %d;" % MAX_MICRO_TIME
        self.result.raw = sql.replace("\$", "$")

        # Execute sql command
        status, records = self.get_sql_result(sql)
        if (status == 0):
            count = records["records"][0][0]
            # expect value : 0
            if int(count) == self.result.epv:
                self.result.rst = ResultStatus.OK
            else:
                self.result.rst = ResultStatus.NG
            vals["transaction"] = count
        else:
            self.result.rst = ResultStatus.ERROR
            vals["except"] = records

        # add resault to json
        self.result.val = json.dumps(vals)



if __name__ == '__main__':
    '''
    main
    '''
    # check if user is root
    ograc_log = setup('ograc') 
    if(os.getuid() == 0):
        ograc_log.error("Cannot use root user for this operation!")
        sys.exit(1)

    # main function
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
