from testing import assert_equal, assert_raises, assert_true
from collections import Optional
from memory import UnsafePointer

from testutils import enforce_mask
from websockets.aliases import Bytes
from websockets.frames import (
    Close,
    Frame,
    CLOSE_CODE_GOING_AWAY,
    CLOSE_CODE_NORMAL_CLOSURE,
    CLOSE_CODE_PROTOCOL_ERROR,
    OP_TEXT,
    OP_CLOSE,
)
from websockets.protocol import Event, CLIENT, SERVER, OPEN
from websockets.protocol.base import (
    receive_data, 
    send_close,
    send_continuation,
    send_text, 
    Protocol,
)
from websockets.streams import StreamReader
from websockets.utils.bytes import str_to_bytes

# 129 is 0x81, 4 is the length of the payload, 83 is 'S', 112 is 'p', 97 is 'a', 109 is 'm'
alias unmasked_text_frame_data = Bytes(129, 4, 83, 112, 97, 109)  
# 129 is 0x81, 132 is 0x84, 0 is the first byte of the mask, 255 is the second byte of the mask
alias masked_text_frame_data = Bytes(129, 132, 0, 255, 0, 255, 83, 143, 97, 146)


@value
struct DummyProtocol[masked: Bool, side_param: Int](Protocol):
    """Protocol that does not mask frames."""
    alias side = side_param
    var state: Int
    var reader: StreamReader
    var writes: Bytes
    var events: List[Event]
    var parser_exc: Optional[Error]
    var curr_size: Optional[Int]
    # Close code and reason, set when a close frame is sent or received.
    var close_rcvd: Optional[Close]
    var close_sent: Optional[Close]
    var close_rcvd_then_sent: Optional[Bool]
    var eof_sent: Bool
    var discard_sent: Bool

    fn __init__(out self, state: Int, reader: StreamReader, writes: Bytes, events: List[Event]):
        self.state = state
        self.reader = reader
        self.writes = writes
        self.events = events
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

    fn is_masked(self) -> Bool:
        """Check if the connection is masked."""
        return masked

    fn get_state(self) -> Int:
        """Get the current state of the connection."""
        return self.state

    fn set_state(mut self, state: Int) -> None:
        """Set the state of the protocol."""
        self.state = state

    fn write_data(mut self, data: Bytes) -> None:
        """Write data to the protocol."""
        self.writes += data

    fn receive_data(mut self, data: Bytes) raises -> None:
        """Receive data from the protocol."""
        res = receive_data(self, data)
        if not res:
            return
        event_and_error = res.value()
        event = event_and_error[0]
        self.add_event(event)
        self.parser_exc = event_and_error[1]

    fn add_event(mut self, event: Event) -> None:
        """Add an event to the protocol."""
        self.events.append(event)

    fn data_to_send(mut self) -> Bytes:
        """Get data to send to the protocol."""
        writes = self.writes^
        self.writes = Bytes()
        return writes

    fn expect_continuation_frame(self) -> Bool:
        """Check if a continuation frame is expected."""
        return False

    fn set_expect_continuation_frame(mut self, value: Bool) -> None:
        """Set the expectation of a continuation frame."""
        pass

    fn events_received(mut self) -> List[Event]:
        """
        Fetch events generated from data received from the network.
        """
        events = self.events^
        self.events = List[Event]()
        return events

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


fn test_client_receives_unmasked_frame() raises:
    reader = StreamReader()
    writes = Bytes()
    events = List[Event]()

    client = DummyProtocol[False, CLIENT](OPEN, reader, writes, events)
    assert_equal(client.is_masked(), False)

    s = Bytes(129, 4) + str_to_bytes("Spam")
    client.receive_data(s)

    events = client.events_received()
    assert_true(events[0].isa[Frame]())
    assert_equal(events[0][Frame].data, Frame(OP_TEXT, str_to_bytes("Spam")).data)
    

fn test_client_sends_masked_frame() raises:
    client = DummyProtocol[True, CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    fn gen_mask() -> Bytes:
        return Bytes(0, 255, 0, 255)
    send_text[gen_mask_func=gen_mask](client, str_to_bytes("Spam"), True)
    assert_equal(client.data_to_send(), masked_text_frame_data)


fn test_server_sends_unmasked_frame() raises:
    server = DummyProtocol[False, SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    send_text(server, str_to_bytes("Spam"), True)
    assert_equal(server.data_to_send(), unmasked_text_frame_data)


fn test_server_receives_masked_frame() raises:
    server = DummyProtocol[True, SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    server.receive_data(masked_text_frame_data)
    events = server.events_received()
    assert_true(events[0].isa[Frame]())
    assert_equal(events[0][Frame].data, Frame(OP_TEXT, str_to_bytes("Spam")).data)


fn test_client_receives_masked_frame() raises:
    client = DummyProtocol[False, CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    client.receive_data(masked_text_frame_data)
    events = client.events_received()
    assert_equal(events[0][Frame], Frame(OP_CLOSE, Close(CLOSE_CODE_PROTOCOL_ERROR, "ProtocolError: incorrect masking").serialize(), fin=True))


fn test_server_receives_unmasked_frame() raises:
    server = DummyProtocol[True, SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    server.receive_data(unmasked_text_frame_data)
    events = server.events_received()
    assert_equal(events[0][Frame], Frame(OP_CLOSE, Close(CLOSE_CODE_PROTOCOL_ERROR, "ProtocolError: incorrect masking").serialize(), fin=True))


fn test_client_sends_unexpected_continuation() raises:
    client = DummyProtocol[False, CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    with assert_raises(contains='ProtocolError: unexpected continuation frame'):
        send_continuation(client, str_to_bytes(""), fin=False)


fn test_server_sends_unexpected_continuation() raises:
    server = DummyProtocol[True, SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    with assert_raises(contains="ProtocolError: unexpected continuation frame"):
        send_continuation(server, str_to_bytes(""), fin=False)


fn test_client_receives_unexpected_continuation() raises:
    client = DummyProtocol[False, CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    client.receive_data(Bytes(0, 0))
    events = client.events_received()
    assert_equal(client.parser_exc.value()._message(), "ProtocolError: unexpected continuation frame")
    assert_equal(events[0][Frame], Frame(OP_CLOSE, Close(CLOSE_CODE_PROTOCOL_ERROR, "ProtocolError: unexpected continuation frame").serialize(), fin=True))


fn test_server_receives_unexpected_continuation() raises:
    server = DummyProtocol[True, SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    server.receive_data(Bytes(0, 128, 0, 0, 0, 0))
    events = server.events_received()
    assert_equal(server.parser_exc.value()._message(), "ProtocolError: unexpected continuation frame")
    assert_equal(events[0][Frame], Frame(OP_CLOSE, Close(CLOSE_CODE_PROTOCOL_ERROR, "ProtocolError: unexpected continuation frame").serialize(), fin=True))


fn test_client_sends_continuation_after_sending_close() raises:
    client = DummyProtocol[True, SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    # Since it isn't possible to send a close frame in a fragmented
    # message (see test_client_send_close_in_fragmented_message), in fact,
    # this is the same test as test_client_sends_unexpected_continuation.
    fn gen_mask() -> Bytes:
        return Bytes(0, 0, 0, 0)
    send_close[gen_mask_func=gen_mask](client, CLOSE_CODE_GOING_AWAY)
    assert_equal(client.data_to_send(), Bytes(136, 130, 0, 0, 0, 0, 3, 233))
    with assert_raises(contains='ProtocolError: unexpected continuation frame'):
        send_continuation(client, str_to_bytes(""), fin=False)


fn test_server_sends_continuation_after_sending_close() raises:
    # Since it isn't possible to send a close frame in a fragmented
    # message (see test_server_send_close_in_fragmented_message), in fact,
    # this is the same test as test_server_sends_unexpected_continuation.
    server = DummyProtocol[False, SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    send_close(server, CLOSE_CODE_NORMAL_CLOSURE)
    assert_equal(server.data_to_send(), Bytes(136, 2, 3, 232))
    with assert_raises(contains='ProtocolError: unexpected continuation frame'):
        send_continuation(server, Bytes(), fin=False)


fn test_client_receives_continuation_after_receiving_close() raises:
    client = DummyProtocol[False, CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    client.receive_data(Bytes(136, 2, 3, 232))
    events = client.events_received()
    assert_equal(len(events), 1)
    close_frame = Frame(OP_CLOSE, Close(CLOSE_CODE_NORMAL_CLOSURE, "").serialize(), fin=True)
    assert_equal(events[0][Frame], close_frame)
    assert_equal(client.data_to_send(), close_frame.serialize(mask=client.is_masked()))

    client.receive_data(Bytes(0, 0))

    events = client.events_received()
    assert_equal(len(events), 0)
    assert_equal(client.data_to_send(), Bytes())
#
#
# fn test_server_receives_continuation_after_receiving_close() raises:
#     server = DummyProtocol[True, SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
#     server.receive_data(Bytes(136, 130, 0, 0, 0, 0, 3, 233))
#     close_frame = Frame(OP_CLOSE, Close(CLOSE_CODE_GOING_AWAY, "").serialize(), fin=True)
#     events = server.events_received()
#     assert_equal(events[0][Frame], close_frame)
#     # self.assertConnectionClosing(server, CLOSE_CODE_GOING_AWAY)
#     # server.receive_data(b"\x00\x80\x00\xff\x00\xff")
#     # self.assertFrameReceived(server, None)
#     # self.assertFrameSent(server, None)
