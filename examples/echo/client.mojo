"""Client example using the threading API."""
from websockets.sync.client import connect
from websockets.utils.bytes import bytes_to_str, str_to_bytes


fn send_and_receive_loop() raises:
    with connect("ws://127.0.0.1:8001") as client:
        while True:
            msg = input("Enter a message: ")
            client.send_text(msg)
            print(">>> ", msg)
            response = client.recv()
            print("<<< ", bytes_to_str(response))


fn main() raises:
    send_and_receive_loop()
