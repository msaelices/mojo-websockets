"""Client example using the threading API."""
from websockets.sync.client import connect


fn send_and_receive_loop() raises:
    with connect("ws://127.0.0.1:8001") as client:
        while True:
            msg = input("Enter a message: ")
            client.send_text(msg)
            print(">>> ", msg)
            response = client.recv_text()
            print("<<< ", response)


fn main() raises:
    send_and_receive_loop()
