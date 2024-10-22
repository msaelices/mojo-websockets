# Code adapted from https://github.com/saviorand/lightbug_http/tree/feature/websocket
# Thanks to @rd4com for the original code
from python import Python
from memory import UnsafePointer
from time import sleep

from libc import (
    fd_set,
    select,
    timeval,
)
from websockets.sync.server import serve, send_message, receive_message


fn main() raises:
    var ws = serve()
    if ws:
        # TODO: Make an abstraction layer to not deal with libc socket FDs
        var conn = ws.value()
        var fds = fd_set()
        var fds_ptr = UnsafePointer[fd_set].address_of(fds)
        var null_ptr = UnsafePointer[fd_set]()
        var null_timeval_ptr = UnsafePointer[timeval]()
        var socket = conn.fd
        fds.set(socket)
        for i in range(32):
            # first argument is the number of file descriptors (TODO: make it dynamic)
            var res = select(socket + 1, fds_ptr, null_ptr, null_ptr, null_timeval_ptr)
            print(res)
            while res != -1:
                _ = send_message(conn, "server waiting")
                # first argument is the number of file descriptors (TODO: make it dynamic)
                res = select(socket + 1, fds_ptr, null_ptr, null_ptr, null_timeval_ptr)
                print("\nwait\n")
                sleep(1)
            m = receive_message(ws.value())
            if m:
                # print(m.value())
                _ = send_message(ws.value(),m.value())
    _ = ws^

