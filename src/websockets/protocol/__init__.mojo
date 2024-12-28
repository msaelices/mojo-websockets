from collections import Optional
from memory import UnsafePointer
from utils import Variant

from websockets.aliases import Bytes
from websockets.frames import Frame, Close
from websockets.http import HTTPRequest, HTTPResponse
from websockets.streams import StreamReader

alias SERVER = 0
alias CLIENT = 1

alias CONNECTING = 0
alias OPEN = 1
alias CLOSING = 2
alias CLOSED = 3

alias SEND_EOF = Bytes()
"""Sentinel signaling that the TCP connection must be half-closed."""

alias Event = Variant[HTTPRequest, HTTPResponse, Frame]


trait Protocol:
    alias side: Int

    fn get_reader_ptr(self) -> UnsafePointer[StreamReader]:
        """Get the pointer to the reader of the protocol."""
        ...

    fn get_state(self) -> Int:
        """Get the state of the protocol."""
        ...

    fn set_state(mut self, state: Int):
        """Set the state of the protocol.

        Args:
            state: The state of the protocol.
        """
        ...

    fn write_data(mut self, data: Bytes) -> None:
        """Write data to the protocol."""
        ...

    fn events_received(mut self) -> List[Event]:
        """
        Fetch events generated from data received from the network.

        Call this method immediately after any of the ``receive_*()`` methods.

        Process resulting events, likely by passing them to the application.

        Returns:
            Events read from the connection.
        """
        ...

    fn add_event(mut self, event: Event) -> None:
        """Add an event to the protocol."""
        ...

    # Public method for getting outgoing data after receiving data or sending events.

    fn data_to_send(mut self) -> Bytes:
        """
        Obtain data to send to the network.

        Call this method immediately after any of the ``receive_*()``,
        ``send_*()``, or `fail` methods.

        Write resulting data to the connection.

        The empty bytestring `~websockets.protocol.SEND_EOF` signals
        the end of the data stream. When you receive it, half-close the TCP
        connection.

        Returns:
            Data to write to the connection.
        """
        ...

    fn expect_continuation_frame(self) -> Bool:
        """Check if a continuation frame is expected."""
        ...

    fn set_expect_continuation_frame(mut self, value: Bool) -> None:
        """Set the expectation of a continuation frame."""
        ...

    fn is_masked(self) -> Bool:
        """Check if the protocol is masked."""
        ...

    fn get_curr_size(self) -> Optional[Int]:
        """Get the current size of the protocol."""
        ...

    fn set_curr_size(mut self, size: Optional[Int]) -> None:
        """Set the current size of the protocol."""
        ...

    fn get_close_rcvd(self) -> Optional[Close]:
        """Get the close frame received."""
        ...

    fn set_close_rcvd(mut self, close: Optional[Close]) -> None:
        """Set the close frame received."""
        ...

    fn get_close_sent(self) -> Optional[Close]:
        """Get the close frame sent."""
        ...

    fn set_close_sent(mut self, close: Optional[Close]) -> None:
        """Set the close frame sent."""
        ...

    fn get_close_rcvd_then_sent(self) -> Optional[Bool]:
        """Check if the close frame was received then sent."""
        ...

    fn set_close_rcvd_then_sent(mut self, value: Optional[Bool]) -> None:
        """Set if the close frame was received then sent."""
        ...

    fn get_eof_sent(self) -> Bool:
        """Check if the EOF was sent."""
        ...

    fn set_eof_sent(mut self, value: Bool) -> None:
        """Set if the EOF was sent."""
        ...

    fn get_discard_sent(self) -> Bool:
        """Get the flag of discarding received data."""
        ...

    fn set_discard_sent(mut self, value: Bool) -> None:
        """Set the flag of discarding received data."""
        ...

    fn get_parser_exc(self) -> Optional[Error]:
        """Get the parser exception."""
        ...

    fn set_parser_exc(mut self, exc: Optional[Error]) -> None:
        """Set the parser exception."""
        ...
