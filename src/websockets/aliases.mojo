alias Byte = UInt8
alias Bytes = List[Byte, True]
alias Duration = Int
alias DEFAULT_BUFFER_SIZE = 4096
alias DEFAULT_MAX_REQUEST_BODY_SIZE = 10 * 1024 * 1024  # 10 MB
alias DEFAULT_TCP_KEEP_ALIVE = Duration(15 * 1000 * 1000 * 1000)  # 15 seconds

# It is a "magic" constant, see:
# https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers#server_handshake_response
alias MAGIC_CONSTANT = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
