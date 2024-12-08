from utils import Variant

from websockets.aliases import Bytes
from websockets.frames import Frame
from websockets.http import HTTPRequest, HTTPResponse
from websockets.streams import StreamReader

alias SERVER = 0
alias CLIENT = 1

alias CONNECTING = 0
alias OPEN = 1
alias CLOSING = 2
alias CLOSED = 3

alias Event = Variant[HTTPRequest, HTTPResponse, Frame]


trait Protocol:

    fn get_state(self) -> Int:
        """Get the state of the protocol."""
        ...

    fn receive_data(inout self, data: Bytes) raises:
        """Feed data and receive frames."""
        ...

    fn write_data(inout self, data: Bytes) -> None:
        """Write data to the protocol."""
        ...

    fn events_received(inout self) -> List[Event]:
        """
        Fetch events generated from data received from the network.

        Call this method immediately after any of the ``receive_*()`` methods.

        Process resulting events, likely by passing them to the application.

        Returns:
            Events read from the connection.
        """
        ...

    fn add_event(inout self, event: Event) -> None:
        """Add an event to the protocol."""
        ...

    # Public method for getting outgoing data after receiving data or sending events.

    fn data_to_send(inout self) -> Bytes:
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

    fn set_expect_continuation_frame(inout self, value: Bool) -> None:
        """Set the expectation of a continuation frame."""
        ...

    fn is_masked(self) -> Bool:
        """Check if the protocol is masked."""
        ...
