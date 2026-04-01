#!/usr/bin/env python3
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


class CheckDBVersion(BaseItem):
    '''
    check version of database
    '''
    def __init__(self):
        super(CheckDBVersion, self).__init__(self.__class__.__name__)
        self.title = "Check the database version"

    def do_check(self):
        '''
        function : Check version of database
        input : NA
        output : NA
        '''

        vals = {}
        self.result.rst = ResultStatus.OK

        cmd = "source ~/.bashrc && %s/ogracd -v | grep -oP \"\K\d+\.\d+\"" % \
              os.path.join(self.context.app_path, "bin")
        self.result.raw = cmd
        status, output = self.get_cmd_result(cmd, self.user)
        if (status == 0):
            vals["db_version"] = output
            cmd = "cat %s | grep -oP 'Version: \K\d+\.\d+'" % _paths.versions_yml
            status, output = self.get_cmd_result(cmd, self.user)
            version_info = vals.get("db_version").strip()
            if version_info and version_info != output.strip(" "):
                self.result.rst = ResultStatus.ERROR
                vals["except"] = "oGRACd version is different from the version.yaml"
            if not version_info:
                raise Exception("Failed to find oGRAC database version info.")
        else:
            self.result.rst = ResultStatus.ERROR
            vals["except"] = output
        self.result.val = json.dumps(vals)


if __name__ == '__main__':
    '''
    main
    '''
    ograc_log = setup('ograc')
    if os.getuid() == 0:
        ograc_log.error("Cannot use root user for this operation!")
        sys.exit(1)

    checker = CheckDBVersion()
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
