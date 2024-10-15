# Code adapted from https://github.com/saviorand/lightbug_http/tree/feature/websocket
# Thanks to @rd4com for the original code
from python import Python
from time import sleep

from websockets.sync.server import websocket, send_message, receive_message


fn main() raises:
    var select = Python.import_module("select").select
    var ws = websocket()
    if ws:
        for _ in range(32):
            var res = select([ws.value()[0]],[],[],0)[0]
            while len(res) == 0:
                _ = send_message(ws.value(), "server waiting")
                res = select([ws.value()[0]],[],[],0)[0]
                print("\nwait\n")
                sleep(1)
            m = receive_message(ws.value())
            if m:
                # print(m.value())
                _ = send_message(ws.value(),m.value())
    _ = ws^
    _ = select^

