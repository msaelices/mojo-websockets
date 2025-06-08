from websockets.aliases import Bytes, DEFAULT_BUFFER_SIZE
from websockets.frames import Frame
from websockets.logger import logger
from websockets.protocol.base import (
    receive_data,
    send_binary,
    send_continuation,
    send_text,
)
from websockets.protocol.client import ClientProtocol
from websockets.net import TCPAddr, TCPConnection
from websockets.socket import Socket
from websockets.utils.bytes import str_to_bytes, bytes_to_str
from websockets.utils.uri import URI


struct Client:
    """
    A client object that can be used to connect to a server.
    """

    var uri: URI
    var conn: TCPConnection
    var protocol: ClientProtocol

    fn __init__(out self, uri: String) raises:
        self.uri = URI.parse(uri)
        self.protocol = ClientProtocol(self.uri)
        var socket: Socket[TCPAddr]
        try:
            socket = Socket[TCPAddr]()
        except e:
            logger.error(e)
            raise Error(
                "Client: Failed to create WS client due to socket creation failure."
            )
        self.conn = TCPConnection(socket^)

    fn __moveinit__(out self, owned other: Self):
        self.protocol = other.protocol^
        self.uri = other.uri^
        self.conn = other.conn^

    fn __copyinit__(out self, other: Self):
        self.protocol = other.protocol
        self.uri = other.uri
        self.conn = other.conn

    # Context manager methods

    fn __enter__(mut self) raises -> Self:
        """
        Context manager entry point, called by the serve() function.

        Usage:
            with connect("ws://localhost:8000") as client:
                client.send_text("Hello world!")
                response = client.recv()
        """
        self.conn.connect(self.uri.get_hostname(), self.uri.get_port())
        conn_req = self.protocol.connect()
        logger.debug("Sending connection request:\n", conn_req)
        self.protocol.send_request(conn_req)
        data_to_send = self.protocol.data_to_send()
        _ = self.conn.write(data_to_send)
        response_bytes = Bytes(capacity=DEFAULT_BUFFER_SIZE)
        bytes_received = self.conn.read(response_bytes)
        logger.debug("Bytes received: ", bytes_received)
        receive_data(self.protocol, response_bytes)
        if self.protocol.get_handshake_exc():
            logger.error(String(self.protocol.get_handshake_exc().value()))
            logger.error("Failed to establish connection. Closing connection.")
            self.close()
            raise self.protocol.get_handshake_exc().value()
        return self

    fn __exit__(
        mut self,
    ) raises -> None:
        """
        Context manager exit point, called by the serve() function, closing the connection.
        """
        self.close()

    # ===-------------------------------------------------------------------=== #
    # Methods
    # ===-------------------------------------------------------------------=== #

    fn send_binary(mut self, message: Bytes) raises -> None:
        """
        Send a message to the server.

        Args:
            message: The message to send.
        """
        send_binary(self.protocol, message)
        _ = self.conn.write(self.protocol.data_to_send())

    fn send_text(mut self, message: String) raises -> None:
        """
        Send a message to the server.

        Args:
            message: The message to send.
        """
        send_text(self.protocol, str_to_bytes(message))
        _ = self.conn.write(self.protocol.data_to_send())

    fn send_continuation(mut self, message: Bytes, fin: Bool = False) raises -> None:
        """
        Send a continuation message to the server.

        Args:
            message: The message to send.
            fin: A boolean indicating if this is the final message in the sequence.
        """
        send_continuation(self.protocol, message, fin=fin)
        _ = self.conn.write(self.protocol.data_to_send())

    fn recv(mut self) raises -> Bytes:
        """
        Receive a message from the server.

        Returns:
            Bytes - The message received.
        """
        var b = Bytes(capacity=DEFAULT_BUFFER_SIZE)
        try:
            _ = self.conn.read(b)
        except e:
            self.close()
            logger.error(e)
            raise e
        receive_data(self.protocol, b)

        events_received = self.protocol.events_received()
        received = Bytes(capacity=DEFAULT_BUFFER_SIZE)
        for event_ref in events_received:
            event = event_ref[]
            if event.isa[Frame]():
                received += event[Frame].data
        # TODO: Handle parse exceptions
        return received

    fn recv_text(mut self) raises -> String:
        """
        Receive a message from the server.

        Returns:
            String - The message received.
        """
        return bytes_to_str(self.recv())

    fn close(mut self) raises -> None:
        """
        Close the connection.
        """
        self.conn.teardown()


fn connect(uri: String) raises -> Client:
    """
    Serve HTTP requests.

    Args:
        uri: The address to connect to.

    Returns:
        Client - A client object that can be used to connect to a server.

    Raises:
        Error - If the connection fails.

    Usage:
        with connect("ws://localhost:8000") as client:
            client.send_text("Hello world!")
            response = client.recv()
    .
    """
    return Client(uri)
