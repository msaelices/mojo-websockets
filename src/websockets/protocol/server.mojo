from collections import Optional

from websockets.aliases import Bytes, DEFAULT_MAX_REQUEST_BODY_SIZE, DEFAULT_BUFFER_SIZE
from websockets.http import HTTPRequest
from websockets.frames import Frame, Close
from websockets.streams import StreamReader
from websockets.utils.bytes import gen_mask

from . import CONNECTING, SERVER, Protocol, Event
from .base import receive_data, receive_frame


struct ServerProtocol[side_param: Int = SERVER](Protocol):
    """
    Sans-I/O implementation of a WebSocket server connection.
    """
    alias side = side_param

    var reader: StreamReader
    var events: List[Event]
    var writes: Bytes
    var state: Int
    var expect_cont_frame: Bool
    var parser_exc: Optional[Error]
    var curr_size: Optional[Int]
    # Close code and reason, set when a close frame is sent or received.
    var close_rcvd: Optional[Close]
    var close_sent: Optional[Close]
    var close_rcvd_then_sent: Optional[Bool]
    var eof_sent: Bool
    var discard_sent: Bool

    fn __init__(out self):
        self.reader = StreamReader()
        self.events = List[Event]()
        self.writes = Bytes(capacity=DEFAULT_BUFFER_SIZE)
        self.state = CONNECTING
        self.expect_cont_frame = False
        self.parser_exc = None
        self.curr_size = None

        self.close_rcvd = None
        self.close_sent = None
        self.close_rcvd_then_sent = None
        self.eof_sent = False
        self.discard_sent = False

    fn get_reader(self) -> StreamReader:
        """Get the reader of the protocol."""
        return self.reader

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
        return True  # Server connections are always masked

    fn receive_data[gen_mask_func: fn () -> Bytes = gen_mask](mut self, data: Bytes) raises -> None:
        """Receive data from the protocol."""
        res = receive_data(self, data)
        # See https://github.com/python-websockets/websockets/blob/59d4dcf779fe7d2b0302083b072d8b03adce2f61/src/websockets/protocol.py#L254
        if not res:
            return
        event_and_error = res.value()
        event = event_and_error[0]
        self.add_event(event)
        self.parser_exc = event_and_error[1]

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

    fn close_expected(self) -> Bool:
        """
        Tell if the TCP connection is expected to close soon.

        Call this method immediately after any of the ``receive_*()``,
        ``send_close()``, or `fail()` methods.

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
