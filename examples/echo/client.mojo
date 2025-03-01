"""Client example using the threading API."""

import sys

from websockets.sync.client import connect
from websockets.utils.bytes import bytes_to_str, str_to_bytes


fn send_and_receive_loop() raises:
    args = sys.argv()
    port = Int(args[1]) if len(args) > 1 else 8001
    with connect("ws://127.0.0.1:{}".format(port)) as client:
        while True:
            msg = input("Enter a message: ")
            client.send_text(msg)
            print(">>> ", msg)
            response = client.recv()
            print("<<< ", bytes_to_str(response))


fn main() raises:
    send_and_receive_loop()
