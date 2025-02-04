"""Client example using the threading API."""
import sys

from websockets.sync.client import connect
from websockets.utils.bytes import bytes_to_str, str_to_bytes


fn send_and_receive(msg: String) raises:
    with connect("ws://127.0.0.1:8000") as client:
        client.send_text(msg)
        print(">>> ", msg)
        response = client.recv()
        print("<<< ", bytes_to_str(response))


fn main() raises:
    args = sys.argv()
    send_and_receive(String(args[1]) if len(args) > 1 else "Hello world!")
