"""Server example using the threading API."""

from websockets.aliases import Bytes
from websockets.sync.server import serve, WSConnection


fn on_message(conn: WSConnection, data: Bytes) raises -> None:
    print("<<< ", String(data))
    conn.send_text(String(data))
    print(">>> ", String(data))


fn main() raises:
    with serve(on_message, "127.0.0.1", 8770) as server:
        server.serve_forever()


