# Code adapted from https://github.com/saviorand/lightbug_http/tree/feature/websocket/
# Thanks to @rd4com for the original code

from base64 import b64encode
from collections import Dict, Optional
from memory import UnsafePointer
from python import Python, PythonObject
from time import sleep

from libc import FD, fd_set, timeval, select

from ..aliases import Bytes, DEFAULT_BUFFER_SIZE, DEFAULT_MAX_REQUEST_BODY_SIZE
from ..http import HTTPRequest, HTTPResponse, encode
from ..net import create_listener, TCPConnection, TCPListener

# It is a "magic" constant, see:
# https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers#server_handshake_response
alias MAGIC_CONSTANT = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

alias BYTE_0_TEXT: UInt8 = 1
alias BYTE_0_NO_FRAGMENT: UInt8 = 128

alias BYTE_1_FRAME_IS_MASKED: UInt8 = 128

alias BYTE_1_SIZE_ONE_BYTE: UInt8 = 125
alias BYTE_1_SIZE_TWO_BYTES: UInt8 = 126
alias BYTE_1_SIZE_EIGHT_BYTES: UInt8 = 127

alias ConnHandler = fn (HTTPRequest) raises -> HTTPResponse


fn serve_old[
    host: StringLiteral = "127.0.0.1", port: Int = 8000
]() -> Optional[TCPConnection]:
    """
    1. Open server
    2. Upgrade first HTTP client to websocket
    3. Close server
    4. return the websocket.
    """
    # TODO: Use the code from the net module instead of `Python.import_module("socket")`

    try:
        var py_sha1 = Python.import_module("hashlib").sha1

        var listener = create_listener(host, port)
        print('Listening on ', host, ':', port)
        listener.listen()

        var conn = listener.accept()
        print('Accepted connection from ', str(conn.raddr))
        print("ws://" + str(host) + ":" + str(port))

        if conn.raddr.ip != "127.0.0.1":
            print("Exit, request from: " + str(conn.raddr.ip))
            conn.close()
            listener.close()
            return None

        # Close server
        listener.close()

        # Get request
        var buf = Bytes(capacity=1024)
        var bytes_read = conn.read(buf)
        var request = String(buf[:bytes_read])
        # TODO: why find("\r\n\r\n") does not work?
        # var end_header = request.find("\r\n\r\n")
        var end_header = request.find("\r\n\r")
        if end_header == -1:
            raise "end_header == -1, no \\r\\n\\r\\n"
        var request_split = str(request)[:end_header].split("\r\n")
        if len(request_split) == 0:
            raise "error: len(request_split) == 0"
        if request_split[0] != "GET / HTTP/1.1":
            raise "request_split[0] not GET / HTTP/1.1"
        _ = request_split.pop(0)

        if len(request_split) == 0:
            raise "error: no headers"

        var request_header = Dict[String, String]()
        for e in request_split:
            var header_pos = e[].find(":")
            if header_pos == -1:
                raise "header_pos == -1"
            if len(e[]) == header_pos + 2:
                raise "len(e[]) == header_pos+2"
            var k = e[][:header_pos]
            var v = e[][header_pos + 2 :]
            request_header[k^] = v^

        print('Request headers:')

        for h in request_header:
            print(h[], request_header[h[]])

        # Upgrade to websocket
        if "Upgrade" not in request_header:
            raise "Not upgrade to websocket"

        if request_header["Upgrade"] != "websocket":
            raise "Not an upgrade to websocket"

        if "Sec-WebSocket-Key" not in request_header:
            raise "No Sec-WebSocket-Key for upgrading to websocket"

        var accept = request_header["Sec-WebSocket-Key"]
        accept += MAGIC_CONSTANT
        accept = b64encode(str(py_sha1(PythonObject(accept).encode()).digest()))

        var response = String("HTTP/1.1 101 Switching Protocols\r\n")
        response += "Upgrade: websocket\r\n"
        response += "Connection: Upgrade\r\n"
        response += "Sec-WebSocket-Accept: "
        response += accept
        response += String("\r\n\r\n")

        print(response)

        _ = conn.write(response)
        return conn^

    except e:
        print(e)

    return None


# fn read_byte(inout ws: PythonObject) raises -> UInt8:
#     return UInt8(int(ws[0].recv(1)[0]))
#
#
# fn receive_message[
#     maximum_default_capacity: Int = 1 << 16
# ](inout ws: PythonObject) -> Optional[String]:
#     # limit to 64kb by default!
#     var res = String("")
#
#     try:
#         _ = read_byte(ws)  # not implemented yet
#         var b = read_byte(ws)
#         if (b & BYTE_1_FRAME_IS_MASKED) == 0:
#             # if client send non-masked frame, connection must be closed
#             # https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers#format
#             ws[0].close()
#             raise "Not masked"
#
#         var byte_size_of_message_size = b ^ BYTE_1_FRAME_IS_MASKED
#         var message_size = 0
#
#         if byte_size_of_message_size <= BYTE_1_SIZE_ONE_BYTE:
#             # when size is <= 125, no need for more bytes
#             message_size = int(byte_size_of_message_size)
#             byte_size_of_message_size = 1
#         elif (
#             byte_size_of_message_size == BYTE_1_SIZE_TWO_BYTES
#             or byte_size_of_message_size == BYTE_1_SIZE_EIGHT_BYTES
#         ):
#             if byte_size_of_message_size == BYTE_1_SIZE_TWO_BYTES:
#                 byte_size_of_message_size = 2
#             elif byte_size_of_message_size == BYTE_1_SIZE_EIGHT_BYTES:
#                 byte_size_of_message_size = 8
#             var bytes = UInt64(0)
#             # is it always big endian ?
#             # next loop is basically reading 4 or 8 bytes (big endian)
#             # (theses will form a number that is the message size)
#             for i in range(byte_size_of_message_size):
#                 bytes |= int(read_byte(ws)) << (
#                     int(byte_size_of_message_size - 1 - i) * 8
#                 )
#             message_size = int(bytes)
#             if bytes & (1 << 63) != 0:
#                 # First bit should always be 0, see step 3:
#                 # https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers#decoding_payload_length
#                 raise "too big"
#         else:
#             raise "error"
#
#         if byte_size_of_message_size == 0:
#             raise "message size is 0"
#
#         # client->server messages should always have a mask
#         # https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers#format
#         var mask = SIMD[DType.uint8, 4](
#             read_byte(ws), read_byte(ws), read_byte(ws), read_byte(ws)
#         )
#
#         # should we always use capacity ?
#         # not good if it is too big ! let's limit it with parameters
#         var capacity = message_size
#         if capacity > maximum_default_capacity:
#             capacity = maximum_default_capacity
#         var bytes_message = List[UInt8](capacity=capacity)
#         for i in range(message_size):
#             bytes_message.append(read_byte(ws) ^ mask[i & 3])
#         bytes_message.append(0)
#
#         var message = String(bytes_message^)
#         print(message_size, len(message))
#         return message^
#     except e:
#         print(e)
#     return None
#

# fn send_message(inout ws: PythonObject, message: String) -> Bool:
#     # return False if an error got raised
#
#     try:
#         var byte_array = Python.evaluate("bytearray")
#         var message_part = PythonObject(message).encode("utf-8")
#         var tmp_len = UInt64(len(message_part))
#
#         var first_part = byte_array(2)
#         first_part[0] = int(BYTE_0_NO_FRAGMENT | BYTE_0_TEXT)
#
#         var bytes_for_size = 0
#         if tmp_len <= int(BYTE_1_SIZE_ONE_BYTE):
#             first_part[1] = tmp_len & 255
#             bytes_for_size = 0
#         else:
#             if tmp_len <= ((1 << 16) - 1):
#                 first_part[1] = int(BYTE_1_SIZE_TWO_BYTES)
#                 bytes_for_size = 2
#             else:
#                 first_part[1] = int(BYTE_1_SIZE_EIGHT_BYTES)
#                 bytes_for_size = 8
#
#         var part_two = byte_array(bytes_for_size)  # 0, 4 or 8 bytes
#         # When len of message need 4 or 8 bytes:
#         for i in range(bytes_for_size):
#             part_two[i] = (tmp_len >> (bytes_for_size - i - 1) * 8) & 255
#
#         ws[0].send(first_part + part_two + message_part)
#         return True
#     except e:
#         print(e)
#         return False

fn read_byte(inout conn: TCPConnection) raises -> UInt8:
    var buf = Bytes(capacity=1)
    return UInt8(conn.read(buf))


fn receive_message[
    maximum_default_capacity: Int = 1 << 16
](inout conn: TCPConnection) -> Optional[String]:
    # limit to 64kb by default!
    try:
        _ = read_byte(conn)  # not implemented yet
        var b = read_byte(conn)
        if (b & BYTE_1_FRAME_IS_MASKED) == 0:
            # if client send non-masked frame, connection must be closed
            # https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers#format
            conn.close()
            raise "Not masked"

        var byte_size_of_message_size = b ^ BYTE_1_FRAME_IS_MASKED
        var message_size = 0

        if byte_size_of_message_size <= BYTE_1_SIZE_ONE_BYTE:
            # when size is <= 125, no need for more bytes
            message_size = int(byte_size_of_message_size)
            byte_size_of_message_size = 1
        elif (
            byte_size_of_message_size == BYTE_1_SIZE_TWO_BYTES
            or byte_size_of_message_size == BYTE_1_SIZE_EIGHT_BYTES
        ):
            if byte_size_of_message_size == BYTE_1_SIZE_TWO_BYTES:
                byte_size_of_message_size = 2
            elif byte_size_of_message_size == BYTE_1_SIZE_EIGHT_BYTES:
                byte_size_of_message_size = 8
            var bytes = UInt64(0)
            # is it always big endian ?
            # next loop is basically reading 4 or 8 bytes (big endian)
            # (theses will form a number that is the message size)
            for i in range(byte_size_of_message_size):
                bytes |= int(read_byte(conn)) << (
                    int(byte_size_of_message_size - 1 - i) * 8
                )
            message_size = int(bytes)
            if bytes & (1 << 63) != 0:
                # First bit should always be 0, see step 3:
                # https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers#decoding_payload_length
                raise "too big"
        else:
            raise "error"

        if byte_size_of_message_size == 0:
            raise "message size is 0"

        # client->server messages should always have a mask
        # https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers#format
        var mask = SIMD[DType.uint8, 4](
            read_byte(conn), read_byte(conn), read_byte(conn), read_byte(conn)
        )

        # should we always use capacity ?
        # not good if it is too big ! let's limit it with parameters
        var capacity = message_size
        if capacity > maximum_default_capacity:
            capacity = maximum_default_capacity
        var bytes_message = List[UInt8](capacity=capacity)
        for i in range(message_size):
            bytes_message.append(read_byte(conn) ^ mask[i & 3])
        bytes_message.append(0)

        var message = String(bytes_message^)
        print(message_size, len(message))
        return message^
    except e:
        print(e)
    return None


fn send_message(inout conn: TCPConnection, message: String) -> Bool:
    # return False if an error got raised

    try:
        var tmp_len: Byte = len(message.as_bytes())

        var first_part = Bytes(capacity=2)
        first_part[0] = int(BYTE_0_NO_FRAGMENT | BYTE_0_TEXT)

        var bytes_for_size = 0
        if tmp_len <= int(BYTE_1_SIZE_ONE_BYTE):
            first_part[1] = tmp_len & 255
            bytes_for_size = 0
        else:
            if tmp_len <= ((1 << 16) - 1):
                first_part[1] = int(BYTE_1_SIZE_TWO_BYTES)
                bytes_for_size = 2
            else:
                first_part[1] = int(BYTE_1_SIZE_EIGHT_BYTES)
                bytes_for_size = 8

        var part_two = Bytes(capacity=bytes_for_size)  # 0, 4 or 8 bytes
        # When len of message need 4 or 8 bytes:
        for i in range(bytes_for_size):
            part_two[i] = (tmp_len >> (bytes_for_size - i - 1) * 8) & 255

        _ = conn.write(first_part + part_two + message)
        return True
    except e:
        print(e)
        return False



@value
struct Server:
    """
    A Mojo-based web server that accept incoming requests and delivers HTTP services.
    """
    # TODO: add an error_handler to the constructor

    var host: String
    var port: Int
    var handler: ConnHandler
    var max_request_body_size: Int
    var tcp_keep_alive: Bool

    var ln: TCPListener

    var connections: List[TCPConnection]
    var read_fds: fd_set
    var write_fds: fd_set

    fn __init__(inout self, host: String, port: Int, handler: ConnHandler, max_request_body_size: Int = 1024, tcp_keep_alive: Bool = False) raises:
        """
        Initialize a new server.

        Args:
            host: String - The address to listen on.
            port: Int - The port to listen on.
            handler : ConnHandler - An object that handles incoming HTTP requests.
            max_request_body_size: Int - The maximum size of the request body.
            tcp_keep_alive: Bool - Whether to keep the connection alive after the request is handled.

        Raises:
            If there is an error while initializing the server.
        """
        self.host = host
        self.port = port
        self.handler = handler
        self.max_request_body_size = max_request_body_size
        self.tcp_keep_alive = tcp_keep_alive
        self.ln = TCPListener()
        self.connections = List[TCPConnection]()
        self.read_fds = fd_set()
        self.write_fds = fd_set()

    fn serve_forever(inout self) raises -> None: # TODO: conditional conformance on main struct , then a default for handler e.g. WebsocketHandshake
        """
        Listen for incoming connections and serve HTTP requests.
        """
        var listener = create_listener(self.host, self.port)
        print('Listening on ', self.host, ':', self.port)
        listener.listen()
        self.serve(listener, self.handler)

    fn serve(inout self, ln: TCPListener, handler: ConnHandler) raises -> None:
        """
        Serve HTTP requests.

        Args:
            ln : TCPListener - TCP server that listens for incoming connections.
            handler : HTTPService - An object that handles incoming HTTP requests.

        Raises:
        If there is an error while serving requests.
        """
        self.ln = ln
        self.connections = List[TCPConnection]()

        while True:
            _ = self.read_fds.clear_all()
            _ = self.write_fds.clear_all()

            self.read_fds.set(int(self.ln.fd))

            var max_fd = self.ln.fd
            for i in range(len(self.connections)):
                var conn = self.connections[i]
                self.read_fds.set(int(conn.fd))
                self.write_fds.set(int(conn.fd))
                
                if conn.fd > max_fd:
                    max_fd = conn.fd
                
            var timeout = timeval(0, 10000)

            var select_result = select(
                max_fd + 1,
                UnsafePointer.address_of(self.read_fds),
                UnsafePointer.address_of(self.write_fds),
                UnsafePointer[fd_set](),
                UnsafePointer.address_of(timeout)
            )
            if select_result == -1:
                print("Select error")
                return
            
            if self.read_fds.is_set(int(self.ln.fd)):
                var conn = self.ln.accept()
                print('Accepted connection from ', str(conn.raddr))
                try: 
                    _ = conn.set_non_blocking(True)
                except e:
                    print("Error setting connnection to non-blocking mode: ", e)
                    conn.close()
                    continue
                self.connections.append(conn)
                if conn.fd > max_fd:
                    max_fd = conn.fd
                    self.read_fds.set(int(conn.fd))
            
            var i = 0
            while i < len(self.connections):
                print("Connection ", i)
                var conn = self.connections[i]
                if self.read_fds.is_set(int(conn.fd)):
                    _ = self.handle_read(conn, handler)
                if self.write_fds.is_set(int(conn.fd)):
                    _ = self.handle_write(conn)
                
                if conn.is_closed():
                    _ = self.connections.pop(i)
                else:
                    i += 1

    fn address(inout self) -> String:
        return self.host + ":" + str(self.port)

    fn handle_read(inout self, inout conn: TCPConnection, handler: ConnHandler) raises -> None:
        var max_request_body_size = self.max_request_body_size
        if max_request_body_size <= 0:
            max_request_body_size = DEFAULT_MAX_REQUEST_BODY_SIZE

        var b = Bytes(capacity=DEFAULT_BUFFER_SIZE)
        var bytes_recv = conn.read(b)
        print("Bytes received: ", bytes_recv)
        
        if bytes_recv == 0:
            # conn.close()
            return

        var request = HTTPRequest.from_bytes(self.address(), max_request_body_size, b^)
        var res = handler(request)

        if not self.tcp_keep_alive:
            _ = res.set_connection_close()

        conn.set_write_buffer(encode(res^))

        # TODO: does this make sense?
        self.write_fds.set(int(conn.fd))
        
        # if not self.tcp_keep_alive:
        #     conn.close()

    fn handle_write(inout self, inout conn: TCPConnection) raises -> None:
        var write_buffer = conn.write_buffer()
        if write_buffer:
            var bytes_sent = conn.write(write_buffer)
            if bytes_sent < len(write_buffer):
                conn.set_write_buffer(write_buffer[bytes_sent:])
            else:
                conn.set_write_buffer(Bytes())

    def shutdown(self) -> None:
        self.ln.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        inout self,
    ) -> None:
        self.shutdown()


fn serve(handler: ConnHandler, host: String, port: Int) raises -> Server:
    """
    Serve HTTP requests.

    Args:
        handler : ConnHandler - An object that handles incoming HTTP requests.
        host : String - The address to listen on.
        port : Int - The port to listen on.

    Returns:
        Server - A server object that can be used to serve requests.
    """
    return Server(host, port, handler)

