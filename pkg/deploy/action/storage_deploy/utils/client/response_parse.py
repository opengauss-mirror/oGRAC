# Copyright (c) 2026 Huawei Technologies Co., Ltd.
# oGRAC is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

# coding=utf-8

class ResponseParse(object):
    def __init__(self, res):
        """

        :rtype: object
        """
        self.res = res

    def get_res_code(self):
        status_code = self.res.status_code
        error_code = -1
        error_des = "failed"
        if status_code == 200:
            res = self.res.json()
            if "error" in res:
                ret_result = res.get('error')
            else:
                ret_result = res.get('result')
            error_code = ret_result['code']
            error_des = ret_result['description']
            if error_des is None or error_code == 0:
                error_des = "success"
        return status_code, int(error_code), error_des

    def get_rsp_data(self):
        status_code = self.res.status_code
        rsp_code = -1
        ret_result = {}
        ret_data = None
        if status_code == 200:
            rsp_code = 0
            if "error" in self.res.json():
                ret_result = self.res.json().get('error')
            if "result" in self.res.json():
                ret_result = self.res.json().get('result')
            ret_data = self.res.json().get('data')
        return rsp_code, ret_result, ret_data

    def get_omtask_rsp_data(self):
        status_code = self.res.status_code
        rsp_code = -1
        ret_result = {}
        ret_data = None
        if status_code == 200:
            rsp_code = 0
            if "error" in self.res.json():
                ret_result = self.res.json().get('error')
            if "result" in self.res.json():
                ret_result = self.res.json().get('result')
            ret_data = self.res.json().get('data')
        return rsp_code, ret_result, ret_data
