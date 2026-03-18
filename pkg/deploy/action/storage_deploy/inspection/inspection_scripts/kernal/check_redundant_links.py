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
 
        cmd = "sh /opt/ograc/action/inspection/inspection_scripts/kernal/check_link_cnt.sh"
        self.result.raw = cmd
        status, output = self.get_cmd_result(cmd, self.user)
        if (status == 0):
            vals["success"] = "Have redundant link."
        else:
            self.result.rst = ResultStatus.ERROR
            vals["except"] = "Do not have redundant link, for details, see the /opt/ograc/dbstor/cgwshowdev.log ."
 
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
    checker = CheckRedundantLinks()
    checker_context = CheckContext()
    checker.run_check(checker_context, ograc_log)