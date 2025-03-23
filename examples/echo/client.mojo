"""Client example using the threading API."""

import sys

from websockets.sync.client import connect


fn send_and_receive_loop() raises:
    args = sys.argv()
    port = Int(args[1]) if len(args) > 1 else 8001
    with connect("ws://127.0.0.1:{}".format(port)) as client:
        while True:
            msg = input("Enter a message: ")
            client.send_text(msg)
            print(">>> ", msg)
            response = client.recv_text()
            print("<<< ", response)


fn main() raises:
    send_and_receive_loop()
