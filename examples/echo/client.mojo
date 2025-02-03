"""Client example using the threading API."""
import sys

from websockets.sync.client import connect


fn echo_client(initial_msg: String) raises:
    with connect("ws://127.0.0.1:8770") as websocket:
        websocket.send_text(initial_msg)
        print(">>> ", initial_msg)

        response = websocket.recv()
        print("<<< ", String(response))

fn main() raises:
    args = sys.argv()
    echo_client(String(args[1]) if len(args) > 1 else "Hello world!")
