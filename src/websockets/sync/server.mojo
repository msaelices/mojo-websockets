# Code adapted from https://github.com/saviorand/lightbug_http/tree/feature/websocket/
# Thanks to @rd4com for the original code

from base64 import b64encode
from collections import Dict, Optional
from memory import UnsafePointer
from time import sleep

from websockets.libc import c_int

from websockets.aliases import (
    Bytes,
    DEFAULT_BUFFER_SIZE,
    DEFAULT_MAX_REQUEST_BODY_SIZE,
    MAGIC_CONSTANT,
)
from websockets.frames import Frame
from websockets.http import Header, Headers, HTTPRequest, HTTPResponse, encode
from websockets.logger import logger
from websockets.net import ListenConfig, TCPConnection, TCPListener
from websockets.protocol import CONNECTING, SERVER
from websockets.protocol.base import receive_data, receive_eof, send_text, send_binary
from websockets.protocol.server import ServerProtocol
from websockets.protocol.client import ClientProtocol
from websockets.utils.bytes import str_to_bytes

alias BYTE_0_TEXT: UInt8 = 1
alias BYTE_0_NO_FRAGMENT: UInt8 = 128

alias BYTE_1_FRAME_IS_MASKED: UInt8 = 128

alias BYTE_1_SIZE_ONE_BYTE: UInt8 = 125
alias BYTE_1_SIZE_TWO_BYTES: UInt8 = 126
alias BYTE_1_SIZE_EIGHT_BYTES: UInt8 = 127


alias ConnHandler = fn (conn: WSConnection, data: Span[Byte]) raises -> None


struct WSConnection:
    """
    A connection object that represents a WebSocket connection.
    """

    var conn_ptr: UnsafePointer[TCPConnection]
    var protocol_ptr: UnsafePointer[ServerProtocol]

    fn __init__(out self, ref conn: TCPConnection, ref protocol: ServerProtocol):
        self.conn_ptr = UnsafePointer(to=conn)
        self.protocol_ptr = UnsafePointer(to=protocol)

    fn read(self, mut buf: Bytes) raises -> None:
        _ = self.conn_ptr[].read(buf)
        receive_data(self.protocol_ptr[], buf)

    fn write(self, buf: Bytes) raises -> Int:
        return self.conn_ptr[].write(buf)

    fn send_text(self, message: String) raises:
        send_text(self.protocol_ptr[], str_to_bytes(message))
        _ = self.write(self.protocol_ptr[].data_to_send())

    fn send_binary(self, message: Bytes) raises:
        send_binary(self.protocol_ptr[], message)
        _ = self.write(self.protocol_ptr[].data_to_send())

    fn close(self) raises -> None:
        self.conn_ptr[].close()


struct Server[
    handler: ConnHandler,
]:
    """
    A Mojo-based web server that accept incoming requests and delivers HTTP services.

    Parameters:
        handler: ConnHandler - A function that handles incoming HTTP requests.
    """

    # TODO: add an error_handler to the constructor

    var host: String
    var port: Int
    var max_request_body_size: Int

    var ln: TCPListener

    fn __init__(
        out self,
        host: String,
        port: Int,
        max_request_body_size: Int = DEFAULT_MAX_REQUEST_BODY_SIZE,
    ) raises:
        """
        Initialize a new server.

        Args:
            host: String - The address to listen on.
            port: Int - The port to listen on.
            max_request_body_size: Int - The maximum size of the request body.

        Raises:
            If there is an error while initializing the server.
        """
        self.host = host
        self.port = port
        self.max_request_body_size = max_request_body_size
        self.ln = TCPListener()

    fn __moveinit__(out self, owned other: Self):
        self.host = other.host
        self.port = other.port
        self.max_request_body_size = other.max_request_body_size
        self.ln = other.ln^

    fn __copyinit__(out self, other: Self):
        self.host = other.host
        self.port = other.port
        self.max_request_body_size = other.max_request_body_size
        self.ln = other.ln

    fn __enter__(self) -> Self:
        """
        Context manager entry point, called by the serve() function.

        Usage:
            with serve(handler, host, port) as server:
                server.serve_forever()
        """
        return self

    fn __exit__(
        mut self,
    ) raises -> None:
        """
        Context manager exit point, called by the serve() function which closes the server.
        """
        self.shutdown()

    # ===-------------------------------------------------------------------=== #
    # Methods
    # ===-------------------------------------------------------------------=== #

    fn serve_forever(mut self) raises:
        """
        Listen for incoming connections and serve HTTP requests.
        """
        var net = ListenConfig()
        var listener = net.listen(self.host, self.port)
        self.serve(listener^)

    fn serve(mut self, owned ln: TCPListener) raises:
        """Serve HTTP requests.

        Args:
            ln: TCP server that listens for incoming connections.

        Raises:
            If there is an error while serving requests.
        """
        while True:
            var conn = ln.accept()
            self.serve_connection(conn)

    fn serve_connection(mut self, mut conn: TCPConnection) raises -> None:
        """Serve a single connection.

        Args:
            conn: A connection object that represents a client connection.

        Raises:
            If there is an error while serving the connection.
        """
        protocol = ServerProtocol()
        # Remote address handling changed in Max 25.3
        logger.debug("Connection accepted!")
        wsconn = WSConnection(conn, protocol)
        while True:
            var b = Bytes(capacity=DEFAULT_BUFFER_SIZE)
            try:
                _ = wsconn.read(b)
            except e:
                conn.teardown()
                logger.error(e)
                return
            logger.debug("Bytes received:", len(b))

            if protocol.get_parser_exc():
                logger.error(String(protocol.get_parser_exc().value()))
                conn.teardown()
                return

            # If the server is set to not support keep-alive connections, or the client requests a connection close, we mark the connection to be closed.
            if protocol.get_state() == CONNECTING:
                var request: HTTPRequest = protocol.events_received()[0][HTTPRequest]

                logger.debug("Starting handshake")

                response = protocol.accept(request)
                if protocol.get_handshake_exc():
                    logger.error(String(protocol.get_handshake_exc().value()))
                    conn.teardown()
                    return

                logger.debug("Sending handshake response")
                protocol.send_response(response)
                data_to_send = protocol.data_to_send()

                bytes_written = conn.write(data_to_send)
                logger.debug("Bytes written:", bytes_written)
            else:
                self.handle_read(protocol, wsconn, b)

            logger.debug("Connection processed")

    fn address(mut self) -> String:
        """
        Get the address of the server.
        """
        return String(self.host, ":", self.port)

    fn handle_read(
        self, mut protocol: ServerProtocol, mut wsconn: WSConnection, data: Bytes
    ) raises -> None:
        """
        Handle incoming data.

        Args:
            protocol: ServerProtocol - The protocol object that handles the connection.
            wsconn: WSConnection - The connection object.
            data: Bytes - The data received from the client.
        """
        bytes_recv = len(data)
        if bytes_recv == 0:
            logger.debug("Received zero bytes. Closing connection.")
            receive_eof(protocol)
            return

        events_received = protocol.events_received()
        for event in events_received:
            if event.isa[Frame]() and event[Frame].is_data():
                data_received = event[Frame].data
                handler(wsconn, data_received)

        data_to_send = protocol.data_to_send()
        if len(data_to_send) > 0:
            bytes_written = wsconn.write(data_to_send)
            logger.debug("Bytes written: ", bytes_written)

    fn shutdown(mut self) raises -> None:
        """
        Shutdown the server.
        """
        self.ln.close()


fn serve[handler: ConnHandler](host: String, port: Int) raises -> Server[handler]:
    """
    Serve HTTP requests.

    Args:
        host : String - The address to listen on.
        port : Int - The port to listen on.

    Parameters:
        handler: ConnHandler - A function that handles incoming HTTP requests.

    Returns:
        Server - A server object that can be used to serve requests.

    Raises:
        If there is an error while serving requests.

    Usage:
        with serve[handler](host, port) as server:
            server.serve_forever()
    .
    """
    return Server[handler](host, port)
