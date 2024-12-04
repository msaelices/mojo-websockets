from utils import Variant

from websockets.aliases import Bytes
from websockets.frames import Frame
from websockets.http import HTTPRequest, HTTPResponse
from websockets.streams import StreamReader

alias CONNECTING = 0
alias OPEN = 1
alias CLOSING = 2
alias CLOSED = 3

alias Event = Variant[HTTPRequest, HTTPResponse, Frame]


trait Protocol:

    fn get_state(inout self) -> Int:
        """Get the state of the protocol."""
        ...

    fn receive_data(inout self, data: Bytes) raises:
        """Feed data and receive frames."""
        pass

    fn events_received(inout self) -> List[Event]:
        """
        Fetch events generated from data received from the network.

        Call this method immediately after any of the ``receive_*()`` methods.

        Process resulting events, likely by passing them to the application.

        Returns:
            Events read from the connection.
        """
        pass

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

