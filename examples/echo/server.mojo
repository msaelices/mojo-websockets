"""Server example using the threading API."""

from websockets.aliases import Bytes
from websockets.sync.server import serve, WSConnection
from websockets.utils.bytes import bytes_to_str


fn on_message(conn: WSConnection, data: Bytes) raises -> None:
    str_received = bytes_to_str(data)
    print("<<< ", str_received)
    conn.send_text(str_received)
    print(">>> ", str_received)


fn main() raises:
    with serve(on_message, "127.0.0.1", 8770) as server:
        server.serve_forever()


