# Copyright (c) 2026 Huawei Technologies Co., Ltd.
# oGRAC is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

import sys
from handle_info import HandleInfo
from uds_client import client_socket


def main(params):
    handle_info = HandleInfo()
    data_to_uds, status = handle_info.input_params_handler(params)
    if not status and handle_info.high_risk_command_judgement():
        receive_data = client_socket(data_to_uds)
        handle_info.receipt_info_handler(receive_data)


if __name__ == '__main__':
    input_params = sys.argv[1:]
    main(input_params)
