from base64 import b64encode
from collections import Optional
from memory import UnsafePointer

from websockets.aliases import (
    Bytes,
    DEFAULT_MAX_REQUEST_BODY_SIZE,
    DEFAULT_BUFFER_SIZE,
    MAGIC_CONSTANT,
)
from websockets.http import (
    get_date_timestamp,
    encode,
    Header,
    Headers,
    HTTPRequest,
)
from websockets.frames import Frame, Close
from websockets.logger import logger
from websockets.streams import StreamReader
from websockets.utils.bytes import b64decode, gen_mask, str_to_bytes
from websockets.utils.handshake import ws_accept_key

from websockets.protocol import CONNECTING, SERVER, Protocol, Event
from websockets.protocol.base import (
    discard,
    parse_buffer,
    receive_data,
    receive_frame,
    send_eof,
)


struct ServerProtocol(Protocol):
    """
    Sans-I/O implementation of a WebSocket server connection.
    """

    alias side = SERVER

    var origins: Optional[List[String]]
    var reader: StreamReader
    var events: List[Event]
    var writes: Bytes
    var state: Int
    var expect_cont_frame: Bool
    var parser_exc: Optional[Error]
    var handshake_exc: Optional[Error]
    var curr_size: Optional[Int]
    # Close code and reason, set when a close frame is sent or received.
    var close_rcvd: Optional[Close]
    var close_sent: Optional[Close]
    var close_rcvd_then_sent: Optional[Bool]
    var eof_sent: Bool
    var discard_sent: Bool
    var _active: Bool  # Track if the protocol is active/used

    fn __moveinit__(mut self, owned existing: Self):
        # Needed as we have a list of protocols in the server for concurrency
        self.origins = existing.origins
        self.reader = existing.reader^
        self.events = existing.events^
        self.writes = existing.writes^
        self.state = existing.state
        self.expect_cont_frame = existing.expect_cont_frame
        self.parser_exc = existing.parser_exc
        self.handshake_exc = existing.handshake_exc
        self.curr_size = existing.curr_size
        self.close_rcvd = existing.close_rcvd
        self.close_sent = existing.close_sent
        self.close_rcvd_then_sent = existing.close_rcvd_then_sent
        self.eof_sent = existing.eof_sent
        self.discard_sent = existing.discard_sent
        self._active = existing._active

    fn __init__(out self, origins: Optional[List[String]] = None):
        self.origins = origins
        self.reader = StreamReader()
        self.events = List[Event]()
        self.writes = Bytes(capacity=DEFAULT_BUFFER_SIZE)
        self.state = CONNECTING
        self.expect_cont_frame = False
        self.parser_exc = None
        self.handshake_exc = None
        self.curr_size = None

        self.close_rcvd = None
        self.close_sent = None
        self.close_rcvd_then_sent = None
        self.eof_sent = False
        self.discard_sent = False
        self._active = False

    fn __copyinit__(out self, other: ServerProtocol):
        self.origins = other.origins

        self.reader = StreamReader()
        # This weirdly makes the copy to cause an error while binding the server socket
        # self.events = other.events
        self.events = List[Event]()
        self.writes = Bytes(capacity=DEFAULT_BUFFER_SIZE)
        self.state = other.state
        self.expect_cont_frame = other.expect_cont_frame
        self.parser_exc = other.parser_exc
        self.handshake_exc = other.handshake_exc
        self.curr_size = other.curr_size

        self.close_rcvd = other.close_rcvd
        self.close_sent = other.close_sent
        self.close_rcvd_then_sent = other.close_rcvd_then_sent
        self.eof_sent = other.eof_sent
        self.discard_sent = other.discard_sent
        self._active = other._active

    # ===-------------------------------------------------------------------=== #
    # Trait implementations
    # ===-------------------------------------------------------------------=== #

    fn get_reader_ptr(self) -> UnsafePointer[StreamReader]:
        """Get the reader of the protocol."""
        return UnsafePointer(to=self.reader)

    fn get_state(self) -> Int:
        """
        Get the current state of the connection.

        Returns:
            The current state of the connection.
        """
        return self.state

    fn set_state(mut self, state: Int):
        """Set the state of the protocol.

        Args:
            state: The state of the protocol.
        """
        logger.debug("Setting state to: ", state)
        self.state = state

    fn write_data(mut self, data: Bytes) -> None:
        """Write data to the protocol."""
        self.writes.extend(data)

    fn events_received(mut self) -> List[Event]:
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

    fn add_event(mut self, event: Event) -> None:
        """
        Add an event to the list of events to return to the application.

        Call this method immediately after any of the ``receive_*()`` methods.

        Args:
            event: Event to add to the list of events.

        """
        self.events.append(event)

    fn process_response(mut self, response: HTTPResponse) raises -> None:
        """Process the handshare response from the server."""
        constrained[
            Self.side == CLIENT,
            "Protocol.process_response() is only available for client connections.",
        ]()

    # Public method for getting outgoing data after receiving data or sending events.

    fn data_to_send(mut self) -> Bytes:
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

    fn expect_continuation_frame(self) -> Bool:
        """Check if a continuation frame is expected."""
        return self.expect_cont_frame

    fn set_expect_continuation_frame(mut self, value: Bool) -> None:
        """Set the expectation of a continuation frame."""
        self.expect_cont_frame = value

    fn get_curr_size(self) -> Optional[Int]:
        """Get the current size of the protocol."""
        return self.curr_size

    fn set_curr_size(mut self, size: Optional[Int]) -> None:
        """Set the current size of the protocol."""
        self.curr_size = size

    fn get_close_rcvd(self) -> Optional[Close]:
        """Get the close frame received."""
        return self.close_rcvd

    fn set_close_rcvd(mut self, close: Optional[Close]) -> None:
        """Set the close frame received."""
        self.close_rcvd = close

    fn get_close_sent(self) -> Optional[Close]:
        """Get the close frame sent."""
        return self.close_sent

    fn set_close_sent(mut self, close: Optional[Close]) -> None:
        """Set the close frame sent."""
        self.close_sent = close

    fn get_close_rcvd_then_sent(self) -> Optional[Bool]:
        """Check if the close frame was received then sent."""
        return self.close_rcvd_then_sent

    fn set_close_rcvd_then_sent(mut self, value: Optional[Bool]) -> None:
        """Set if the close frame was received then sent."""
        self.close_rcvd_then_sent = value

    fn get_eof_sent(self) -> Bool:
        """Check if the EOF was sent."""
        return self.eof_sent

    fn set_eof_sent(mut self, value: Bool) -> None:
        """Set if the EOF was sent."""
        self.eof_sent = value

    fn get_discard_sent(self) -> Bool:
        """Get the flag of discarding received data."""
        return self.discard_sent

    fn set_discard_sent(mut self, value: Bool) -> None:
        """Set the flag of discarding received data."""
        self.discard_sent = value

    fn get_parser_exc(self) -> Optional[Error]:
        """Get the parser exception."""
        return self.parser_exc

    fn set_parser_exc(mut self, exc: Optional[Error]) -> None:
        """Set the parser exception."""
        self.parser_exc = exc

    fn get_handshake_exc(self) -> Optional[Error]:
        """Get the handshake exception."""
        return self.handshake_exc

    fn set_handshake_exc(mut self, exc: Optional[Error]) -> None:
        """Set the handshake exception."""
        self.handshake_exc = exc

    fn is_active(self) -> Bool:
        """Return True if this protocol is active/in use."""
        return self._active

    fn set_active(mut self):
        """Mark this protocol as active/in use."""
        self._active = True

    fn set_inactive(mut self):
        """Mark this protocol as inactive/available."""
        self._active = False

    # ===-------------------------------------------------------------------=== #
    # Methods
    # ===-------------------------------------------------------------------=== #

    fn accept[
        date_func: fn () -> String = get_date_timestamp
    ](mut self, request: HTTPRequest) raises -> HTTPResponse:
        """
        Accept a WebSocket connection.

        Args:
            request: The HTTP request to accept.
        """
        try:
            if "Upgrade" not in request.headers:
                raise Error('Request headers do not contain an "upgrade" header')

            if "Connection" not in request.headers:
                # This should return a 426 status code (Upgrade Required) not a 400
                raise Error('Request headers do not contain an "connection" header')

            if request.headers["connection"].lower() != "upgrade":
                raise Error('Request "connection" header is not "upgrade"')

            if request.headers["upgrade"] != "websocket":
                raise Error('Request "upgrade" header is not "websocket"')

            if "Sec-WebSocket-Key" not in request.headers:
                raise Error('Missing "Sec-WebSocket-Key" header.')

            if "Sec-WebSocket-Version" not in request.headers:
                raise Error('Missing "Sec-WebSocket-Version" header.')

            if request.headers["Sec-WebSocket-Version"] != "13":
                raise Error('Request "Sec-WebSocket-Version" header is not "13"')

            if self.origins is not None and "Origin" not in request.headers:
                raise Error('Missing "Origin" header.')

            if self.origins is not None and "Origin" in request.headers:
                if request.headers["Origin"] not in self.origins.value():
                    raise Error('Invalid "Origin" header: ' + request.headers["Origin"])

            # Validate the base64 encoded Sec-WebSocket-Key
            _ = b64decode[validate=True](request.headers["Sec-WebSocket-Key"])
        except exc:
            # TODO: Handle specific exceptions with different status codes.
            self.set_handshake_exc(exc)
            body = String(exc)
            status_code = 400
            status_text = "Bad Request"
            return self.reject[date_func=date_func](status_code, status_text, body)

        var key = request.headers["Sec-WebSocket-Key"]
        var accept_encoded = ws_accept_key(key)
        var headers = Headers(
            Header("Date", date_func()),
            Header("Upgrade", "websocket"),
            Header("Connection", "Upgrade"),
            Header("Sec-WebSocket-Accept", accept_encoded),
            # Header("Sec-WebSocket-Extensions", '""'),
        )

        return HTTPResponse(101, "Switching Protocols", headers, Bytes())

    fn send_response(mut self, response: HTTPResponse) raises -> None:
        """
        Send a handshake response to the client.

        Args:
            response: WebSocket handshake response event to send.

        """
        self.write_data(encode(response))

        if response.status_code == 101:
            if self.get_state() != CONNECTING:
                raise Error("InvalidState: connection is not in CONNECTING state")
            self.set_state(OPEN)
        else:
            # handshake_exc may be already set if accept() encountered an error.
            # If the connection isn't open, set handshake_exc to guarantee that
            # handshake_exc is None if and only if opening handshake succeeded.
            if self.handshake_exc is None:
                self.handshake_exc = Error(String("InvalidStatus: ", response))

            send_eof(self)
            discard(self)
            # Equivalent to the next(self.parser) in the Python implementation
            _ = parse_buffer(self)

    fn reject[
        date_func: fn () -> String = get_date_timestamp,
    ](mut self, status_code: Int, status_text: String, body: String) -> HTTPResponse:
        """
        Fail the WebSocket connection.

        Args:
            status_code: The status code to send.
            status_text: The status text to send.
            body: The body of the response.

        Returns:
            The HTTP response to send to the client.
        """
        var headers = Headers(
            Header("Date", date_func()),
            Header("Connection", "close"),
            Header("Content-Length", String(len(body))),
            Header("Content-type", "text/plain; charset=utf-8"),
        )
        return HTTPResponse(status_code, status_text, headers, str_to_bytes(body))
