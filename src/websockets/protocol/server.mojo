from websockets.aliases import Bytes, DEFAULT_MAX_REQUEST_BODY_SIZE
from websockets.http import HTTPRequest
from websockets.frames import Frame
from websockets.streams import StreamReader

from . import CONNECTING, Protocol, Event, parse


struct ServerProtocol(Protocol):
    """
    Sans-I/O implementation of a WebSocket server connection.
    """
    var reader: StreamReader
    var events: List[Event]
    var writes: Bytes
    var state: Int

    fn __init__(inout self) -> None:
        self.reader = StreamReader()
        self.events = List[Event]()
        self.writes = Bytes()
        self.state = CONNECTING

    fn receive_data(inout self, data: Bytes) raises:
        """Feed data and receive frames."""
        # See https://github.com/python-websockets/websockets/blob/59d4dcf779fe7d2b0302083b072d8b03adce2f61/src/websockets/protocol.py#L254
        self.reader.feed_data(data)
        self.parse(data)

    fn parse(inout self, data: Bytes) raises:
        """Parse a frame from a bytestring."""
        # See https://github.com/python-websockets/websockets/blob/59d4dcf779fe7d2b0302083b072d8b03adce2f61/src/websockets/server.py#L549
        if self.state == CONNECTING:
            response = HTTPRequest.from_bytes(
                'http://localhost',   # TODO: Use actual host
                DEFAULT_MAX_REQUEST_BODY_SIZE,
                data, 
            )
            self.events.append(response)
        else:
            frame = parse(self.reader, data, mask=True)
            self.events.append(frame)

    fn events_received(inout self) -> List[Event]:
        """
        Fetch events generated from data received from the network.

        Call this method immediately after any of the ``receive_*()`` methods.

        Process resulting events, likely by passing them to the application.

        Returns:
            Events read from the connection.
        """
        events = self.events^
        self.events = List[Event]()
        return events

    # Public method for getting outgoing data after receiving data or sending events.

    fn data_to_send(inout self) -> Bytes:
        """
        Obtain data to send to the network.

        Call this method immediately after any of the `receive_*()`,
        `send_*()`, or `fail` methods.

        Write resulting data to the connection.

        The empty bytestring `websockets.protocol.SEND_EOF` signals
        the end of the data stream. When you receive it, half-close the TCP
        connection.

        Returns:
            Data to write to the connection.

        """
        # See https://github.com/python-websockets/websockets/blob/59d4dcf779fe7d2b0302083b072d8b03adce2f61/src/websockets/protocol.py#L494
        writes = self.writes^
        self.writes = Bytes()
        return writes

    fn close_expected(self) -> Bool:
        """
        Tell if the TCP connection is expected to close soon.

        Call this method immediately after any of the ``receive_*()``,
        ``send_close()``, or :meth:`fail` methods.

        If it returns :obj:`True`, schedule closing the TCP connection after a
        short timeout if the other side hasn't already closed it.

        Returns:
            Whether the TCP connection is expected to close soon.

        """
        # We expect a TCP close if and only if we sent a close frame:
        # * Normal closure: once we send a close frame, we expect a TCP close:
        #   server waits for client to complete the TCP closing handshake;
        #   client waits for server to initiate the TCP closing handshake.
        # * Abnormal closure: we always send a close frame and the same logic
        #   applies, except on EOFError where we don't send a close frame
        #   because we already received the TCP close, so we don't expect it.
        # We already got a TCP Close if and only if the state is CLOSED.
        # See https://github.com/python-websockets/websockets/blob/59d4dcf779fe7d2b0302083b072d8b03adce2f61/src/websockets/protocol.py#L514

        # TODO: Implement the handshake_exc logic
        return self.state == CLOSING  # or self.handshake_exc is not None

