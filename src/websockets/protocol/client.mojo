from base64 import b64encode
from collections import Optional
from memory import UnsafePointer
from python import Python, PythonObject

from websockets.aliases import Bytes, DEFAULT_MAX_REQUEST_BODY_SIZE, DEFAULT_BUFFER_SIZE, MAGIC_CONSTANT
from websockets.http import (
    build_host_header,
    build_authorization_basic,
    get_date_timestamp,
    encode,
    Header,
    Headers,
    HTTPRequest,
)
from websockets.frames import Frame, Close
from websockets.protocol import CONNECTING, CLIENT, Protocol, Event
from websockets.protocol.base import (
    discard,
    parse_buffer,
    receive_data,
    receive_frame,
    send_eof,
)
from websockets.streams import StreamReader
from websockets.utils.bytes import b64decode, gen_token, str_to_bytes,gen_mask
from websockets.utils.handshake import ws_accept_key
from websockets.utils.uri import URI



struct ClientProtocol(Protocol):
    """
    Sans-I/O implementation of a WebSocket client connection.
    """
    alias side = CLIENT

    var key: String
    var wsuri: URI
    var origin: Optional[String]
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

    fn __init__(out self, owned uri: URI, owned key: Optional[String] = None, owned origin: Optional[String] = None):
        if not key:
            self.key = b64encode(gen_token(16))
        else:
            self.key = key.value()
        self.wsuri = uri
        self.origin = origin^
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

    fn __copyinit__(out self, other: ClientProtocol):
        self.key = other.key
        self.wsuri = other.wsuri
        self.origin = other.origin

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

    # ===-------------------------------------------------------------------=== #
    # Trait implementations
    # ===-------------------------------------------------------------------=== #

    fn get_reader_ptr(self) -> UnsafePointer[StreamReader]:
        """Get the reader of the protocol."""
        return UnsafePointer.address_of(self.reader)

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
        self.state = state

    fn is_masked(self) -> Bool:
        """
        Check if the connection is masked.

        Returns:
            Whether the connection is masked.
        """
        return False  # Client connections are always non-masked

    fn write_data(mut self, data: Bytes) -> None:
        """Write data to the protocol."""
        self.writes += data

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

    # ===-------------------------------------------------------------------=== #
    # Methods
    # ===-------------------------------------------------------------------=== #

    fn connect(self) raises -> HTTPRequest:
        """
        Create a handshake request to open a connection.

        You must send the handshake request with :meth:`send_request`.

        You can modify it before sending it, for example to add HTTP headers.

        Returns:
            WebSocket handshake request event to send to the server.

        """
        is_secure = self.wsuri.is_wss()
        host_header = build_host_header(
            self.wsuri.get_hostname(), self.wsuri.get_port(), is_secure
        )

        var headers = Headers(
            Header("Host", host_header),
            Header("Upgrade", "websocket"),
            Header("Connection", "Upgrade"),
            Header("Sec-WebSocket-Key", self.key),
            Header("Sec-WebSocket-Version", "13"),
        )
        if self.origin:
            headers["Origin"] = self.origin.value()

        opt_user_info = self.wsuri.get_user_info()
        if opt_user_info:
            user_info = opt_user_info.value()
            headers["Authorization"] = build_authorization_basic(user_info[0], user_info[1])

        # if self.available_extensions is not None:
        #     extensions_header = build_extension(
        #         [
        #             (extension_factory.name, extension_factory.get_request_params())
        #             for extension_factory in self.available_extensions
        #         ]
        #     )
        #     headers["Sec-WebSocket-Extensions"] = extensions_header
        #
        # if self.available_subprotocols is not None:
        #     protocol_header = build_subprotocol(self.available_subprotocols)
        #     headers["Sec-WebSocket-Protocol"] = protocol_header

        return HTTPRequest(self.wsuri, headers=headers)

    fn send_request(mut self, request: HTTPRequest) raises -> None:
        """
        Send a handshake request to the server.

        Args:
            request: WebSocket handshake request event.
        """
        self.write_data(encode(request))

    fn process_response(mut self, response: HTTPResponse) raises -> None:
        """Process the handshare response from the server."""
        constrained[Self.side == CLIENT, "Protocol.process_response() is only available for client connections."]()

        if response.status_code != 101:
            raise Error("InvalidStatus: {}".format(response.status_code))

        headers = response.headers

        # TODO: Support for several "Connection" headers
        # See process_response in the Python implementation
        if "Connection" not in response.headers:
            raise Error('InvalidHeader: Missing "Connection" header')

        connection = response.headers["Connection"]

        if connection.lower() != "upgrade":
            raise Error('InvalidUpgrade: Response "Connection" header is not "Upgrade"')

        if "Upgrade" not in response.headers:
            raise Error('InvalidHeader: Missing "Upgrade" header')

        # TODO: Support for several "Upgrade" headers
        # See process_response in the Python implementation
        upgrade = response.headers["Upgrade"]

        if upgrade != "websocket":
            raise Error('InvalidUpgrade: Response "Upgrade" header is not "websocket"')

        if "Sec-WebSocket-Accept" not in response.headers:
            raise Error('InvalidHeader: Missing "Sec-WebSocket-Accept" header')

        s_w_accept = response.headers["Sec-WebSocket-Accept"]
        if s_w_accept != ws_accept_key(self.key):
            raise Error('InvalidHeader: "Sec-WebSocket-Accept" header is invalid')

        self.set_state(OPEN)
