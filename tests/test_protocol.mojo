from testing import assert_equal, assert_true

from testutils import enforce_mask
from websockets.aliases import Bytes
from websockets.frames import Frame, OP_TEXT
from websockets.protocol import Event, CLIENT, SERVER, OPEN
from websockets.protocol.base import receive_data, send_text, Protocol
from websockets.streams import StreamReader
from websockets.utils.bytes import str_to_bytes

# 129 is 0x81, 4 is the length of the payload, 83 is 'S', 112 is 'p', 97 is 'a', 109 is 'm'
alias unmasked_text_frame_data = Bytes(129, 4, 83, 112, 97, 109)  
# 129 is 0x81, 132 is 0x84, 0 is the first byte of the mask, 255 is the second byte of the mask
alias masked_text_frame_data = Bytes(129, 132, 0, 255, 0, 255, 83, 143, 97, 146)

@value
struct DummyProtocol[masked: Bool](Protocol):
    """Protocol that does not mask frames."""
    var state: Int
    var reader: StreamReader
    var writes: Bytes
    var events: List[Event]

    fn is_masked(self) -> Bool:
        """Check if the connection is masked."""
        return masked

    fn get_state(self) -> Int:
        """Get the current state of the connection."""
        return self.state

    fn write_data(inout self, data: Bytes) -> None:
        """Write data to the protocol."""
        self.writes += data

    fn receive_data(inout self, data: Bytes) raises -> None:
        """Receive data from the protocol."""
        self.add_event(receive_data(self.reader, self.get_state(), data))

    fn add_event(inout self, event: Event) -> None:
        """Add an event to the protocol."""
        self.events.append(event)

    fn data_to_send(inout self) -> Bytes:
        """Get data to send to the protocol."""
        return self.writes

    fn expect_continuation_frame(self) -> Bool:
        """Check if a continuation frame is expected."""
        return False

    fn set_expect_continuation_frame(inout self, value: Bool) -> None:
        """Set the expectation of a continuation frame."""
        pass

    fn events_received(inout self) -> List[Event]:
        """
        Fetch events generated from data received from the network.
        """
        return self.events


fn test_client_receives_unmasked_frame() raises:
    reader = StreamReader()
    writes = Bytes()
    events = List[Event]()

    client = DummyProtocol[False](OPEN, reader, writes, events)
    assert_equal(client.is_masked(), False)

    s = Bytes(129, 4) + str_to_bytes("Spam")
    client.receive_data(s)

    events = client.events_received()
    assert_true(events[0].isa[Frame]())
    assert_equal(events[0][Frame].data, Frame(OP_TEXT, str_to_bytes("Spam")).data)
    

fn test_client_sends_masked_frame() raises:
    client = DummyProtocol[False](OPEN, StreamReader(), Bytes(), List[Event]())
    with enforce_mask(str_to_bytes("\x00\xff\x00\xff")):
        send_text(client, str_to_bytes("Spam"), True)
    assert_equal(client.data_to_send(), masked_text_frame_data)


fn test_server_sends_unmasked_frame() raises:
    server = DummyProtocol[False](OPEN, StreamReader(), Bytes(), List[Event]())
    send_text(server, str_to_bytes("Spam"), True)
    assert_equal(server.data_to_send(), unmasked_text_frame_data)

#
# fn test_client_receives_unmasked_frame():
#     client = Protocol(CLIENT)
#     client.receive_data(self.unmasked_text_frame_date)
#     self.assertFrameReceived(
#         client,
#         Frame(OP_TEXT, b"Spam"),
#     )
#
# fn test_server_receives_masked_frame():
#     server = Protocol(SERVER)
#     server.receive_data(self.masked_text_frame_data)
#     self.assertFrameReceived(
#         server,
#         Frame(OP_TEXT, b"Spam"),
#     )
#
# fn test_client_receives_masked_frame():
#     client = Protocol(CLIENT)
#     client.receive_data(self.masked_text_frame_data)
#     self.assertIsInstance(client.parser_exc, ProtocolError)
#     self.assertEqual(str(client.parser_exc), "incorrect masking")
#     self.assertConnectionFailing(
#         client, CloseCode.PROTOCOL_ERROR, "incorrect masking"
#     )
#
# fn test_server_receives_unmasked_frame():
#     server = Protocol(SERVER)
#     server.receive_data(self.unmasked_text_frame_date)
#     self.assertIsInstance(server.parser_exc, ProtocolError)
#     self.assertEqual(str(server.parser_exc), "incorrect masking")
#     self.assertConnectionFailing(
#         server, CloseCode.PROTOCOL_ERROR, "incorrect masking"
#     )
