import json
import socket
from pathlib import Path

SERVER_ADDRESS = str(Path(__file__).resolve().parents[1] / 'og_om.sock')
SOCKET_TYPE = socket.SOCK_STREAM
SOCKET_FAMILY = socket.AF_UNIX
RECEIVE_DATA_SIZE = 1024


def client_socket(send_data):
    with socket.socket(SOCKET_FAMILY, SOCKET_TYPE) as sock:
        sock.connect(SERVER_ADDRESS)
        sock.sendall(json.dumps(send_data).encode())
        recv_data = sock.recv(RECEIVE_DATA_SIZE).decode()
    return recv_data
