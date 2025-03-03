"""WebSocket server example using io_uring for concurrency."""

import sys

from websockets.aliases import Bytes
from websockets.sync.server import serve, WSConnection


fn on_message(conn: WSConnection, data: Bytes) raises -> None:
    str_received = String(data)
    print("<<< ", str_received)
    conn.send_text(str_received)
    print(">>> ", str_received)


fn main() raises:
    print("Starting WebSocket echo server with io_uring concurrency support")
    print("Multiple clients can connect simultaneously")
    args = sys.argv()
    port = Int(args[1]) if len(args) > 1 else 8001
    with serve(on_message, "127.0.0.1", port) as server:
        server.serve_forever()
