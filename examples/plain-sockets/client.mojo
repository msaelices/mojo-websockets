from libc import socket, AF_INET, SOCK_STREAM

from websockets.aliases import DEFAULT_BUFFER_SIZE, Bytes
from websockets.net import create_connection


fn main() raises:
    var host_str = '127.0.0.1'
    var port = 8000

    var conn = create_connection(host_str, port)
    var bytes_sent = conn.write("GET / HTTP/1.1\r\n\r\n")
    if bytes_sent == -1:
        raise Error("Failed to send message")

    var new_buf = Bytes(capacity=DEFAULT_BUFFER_SIZE)
    var bytes_recv = conn.read(new_buf)
    print('Received the bytes: ', String(new_buf))

    if bytes_recv == 0:
        conn.close()
