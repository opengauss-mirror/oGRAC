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
import socket

SERVER_ADDRESS = '/opt/ograc/og_om/service/og_om.sock'
SOCKET_TYPE = socket.SOCK_STREAM
SOCKET_FAMILY = socket.AF_UNIX
RECEIVE_DATA_SIZE = 1024


def client_socket(send_data):
    with socket.socket(SOCKET_FAMILY, SOCKET_TYPE) as sock:
        sock.connect(SERVER_ADDRESS)
        sock.sendall(json.dumps(send_data).encode())
        recv_data = sock.recv(RECEIVE_DATA_SIZE).decode()
    return recv_data
