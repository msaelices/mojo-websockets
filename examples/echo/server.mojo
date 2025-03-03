"""Server example using the threading API."""

from websockets.aliases import Bytes
from websockets.sync.server import serve, WSConnection


fn on_message(conn: WSConnection, data: Bytes) raises -> None:
    str_received = String(data)
    print("<<< ", str_received)
    conn.send_text(str_received)
    print(">>> ", str_received)


fn main() raises:
    with serve(on_message, "127.0.0.1", 8001) as server:
        server.serve_forever()


