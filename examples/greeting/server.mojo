"""Server example using the threading API."""

from websockets.aliases import Bytes
from websockets.sync.server import serve
from websockets.net import TCPConnection


fn on_message(conn: TCPConnection, data: Bytes) raises -> None:
    print("<<< {}".format(String(data)))


fn main() raises:
    with serve(on_message, "127.0.0.1", 8765) as server:
        server.serve_forever()


