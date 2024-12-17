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
from websockets.utils.bytes import str_to_bytes, gen_mask

# 129 is 0x81, 4 is the length of the payload, 83 is 'S', 112 is 'p', 97 is 'a', 109 is 'm'
alias unmasked_text_frame_data = Bytes(129, 4, 83, 112, 97, 109)  
# 129 is 0x81, 132 is 0x84, 0 is the first byte of the mask, 255 is the second byte of the mask
alias masked_text_frame_data = Bytes(129, 132, 0, 255, 0, 255, 83, 143, 97, 146)

# '😀' is 240, 159, 152, 128
alias smiley_data = Bytes(240, 159, 152, 128)

# 129 is 0x81, 132 is 0x84, 0 is the first byte of the mask, 0 is the second byte of the mask, 240, ... is '😀'
alias smiley_masked_text_frame_data = Bytes(129, 132, 0, 0, 0, 0) + smiley_data


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

    fn get_parser_exc(self) -> Optional[Error]:
        """Get the parser exception."""
        return self.parser_exc

    fn set_parser_exc(mut self, exc: Optional[Error]) -> None:
        """Set the parser exception."""
        self.parser_exc = exc


fn test_client_receives_unmasked_frame() raises:
    reader = StreamReader()
    writes = Bytes()
    events = List[Event]()

    client = DummyProtocol[False, CLIENT](OPEN, reader, writes, events)
    assert_equal(client.is_masked(), False)

    s = Bytes(129, 4) + str_to_bytes("Spam")
    receive_data(client, s)

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
    receive_data(server, masked_text_frame_data)
    events = server.events_received()
    assert_true(events[0].isa[Frame]())
    assert_equal(events[0][Frame].data, Frame(OP_TEXT, str_to_bytes("Spam")).data)


fn test_client_receives_masked_frame() raises:
    client = DummyProtocol[False, CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data(client, masked_text_frame_data)
    events = client.events_received()
    assert_equal(events[0][Frame], Frame(OP_CLOSE, Close(CLOSE_CODE_PROTOCOL_ERROR, "ProtocolError: incorrect masking").serialize(), fin=True))


fn test_server_receives_unmasked_frame() raises:
    server = DummyProtocol[True, SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data(server, unmasked_text_frame_data)
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
    receive_data(client, Bytes(0, 0))
    events = client.events_received()
    assert_equal(client.parser_exc.value()._message(), "ProtocolError: unexpected continuation frame")
    assert_equal(events[0][Frame], Frame(OP_CLOSE, Close(CLOSE_CODE_PROTOCOL_ERROR, "ProtocolError: unexpected continuation frame").serialize(), fin=True))


fn test_server_receives_unexpected_continuation() raises:
    server = DummyProtocol[True, SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data(server, Bytes(0, 128, 0, 0, 0, 0))
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
    receive_data(client, Bytes(136, 2, 3, 232))
    events = client.events_received()
    assert_equal(len(events), 1)
    close_frame = Frame(OP_CLOSE, Close(CLOSE_CODE_NORMAL_CLOSURE, "").serialize(), fin=True)
    assert_equal(events[0][Frame], close_frame)
    assert_equal(client.data_to_send(), close_frame.serialize[gen_mask_func=gen_mask](mask=client.is_masked()))

    receive_data(client, Bytes(0, 0))

    events = client.events_received()
    assert_equal(len(events), 0)
    assert_equal(client.data_to_send(), Bytes())


fn test_server_receives_continuation_after_receiving_close() raises:
    server = DummyProtocol[True, SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    fn gen_mask() -> Bytes:
        return Bytes(0, 0, 0, 0)
    receive_data[gen_mask_func=gen_mask](server, Bytes(136, 130, 0, 0, 0, 0, 3, 233))
    events = server.events_received()
    close_frame = Frame(OP_CLOSE, Close(CLOSE_CODE_GOING_AWAY, "").serialize(), fin=True)
    assert_equal(events[0][Frame], close_frame)
    assert_equal(server.data_to_send(), close_frame.serialize[gen_mask_func=gen_mask](mask=server.is_masked()))
    receive_data(server, Bytes(0, 128, 0, 255, 0, 255))

    events = server.events_received()
    assert_equal(len(events), 0)
    assert_equal(server.data_to_send(), Bytes())


fn test_client_sends_text() raises:
    client = DummyProtocol[True, CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    fn gen_mask() -> Bytes:
        return Bytes(0, 0, 0, 0)
    send_text[gen_mask_func=gen_mask](client, str_to_bytes("Hello world"))
    data_to_send = client.data_to_send()
    for c in data_to_send:
        print("Data to send: ", c[])

    expected = Bytes(129, 139, 0, 0, 0, 0, 72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100) 
    assert_equal(data_to_send, expected)


fn test_server_sends_text() raises:
    server = DummyProtocol[False, SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    send_text(server, str_to_bytes("Hello world"))
    expected = Bytes(129, 11, 72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100)
    assert_equal(server.data_to_send(), expected)


fn test_client_receives_text() raises:
    client = DummyProtocol[True, CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data(client, smiley_masked_text_frame_data)
    expected_frame = Frame(OP_TEXT, smiley_data)

    events = client.events_received()
    assert_equal(events[0][Frame], expected_frame)


fn test_server_receives_text() raises:
    server = DummyProtocol[True, SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data(server, smiley_masked_text_frame_data)
    expected_frame = Frame(OP_TEXT, smiley_data)

    events = server.events_received()
    assert_equal(events[0][Frame], expected_frame)

    #
    # def test_client_receives_text_over_size_limit(self):
    #     client = Protocol(CLIENT, max_size=3)
    #     client.receive_data(b"\x81\x04\xf0\x9f\x98\x80")
    #     self.assertIsInstance(client.parser_exc, PayloadTooBig)
    #     self.assertEqual(str(client.parser_exc), "over size limit (4 > 3 bytes)")
    #     self.assertConnectionFailing(
    #         client, CloseCode.MESSAGE_TOO_BIG, "over size limit (4 > 3 bytes)"
    #     )
    #
    # def test_server_receives_text_over_size_limit(self):
    #     server = Protocol(SERVER, max_size=3)
    #     server.receive_data(b"\x81\x84\x00\x00\x00\x00\xf0\x9f\x98\x80")
    #     self.assertIsInstance(server.parser_exc, PayloadTooBig)
    #     self.assertEqual(str(server.parser_exc), "over size limit (4 > 3 bytes)")
    #     self.assertConnectionFailing(
    #         server, CloseCode.MESSAGE_TOO_BIG, "over size limit (4 > 3 bytes)"
    #     )
    #
    # def test_client_receives_text_without_size_limit(self):
    #     client = Protocol(CLIENT, max_size=None)
    #     client.receive_data(b"\x81\x04\xf0\x9f\x98\x80")
    #     self.assertFrameReceived(
    #         client,
    #         Frame(OP_TEXT, "😀".encode()),
    #     )
    #
    # def test_server_receives_text_without_size_limit(self):
    #     server = Protocol(SERVER, max_size=None)
    #     server.receive_data(b"\x81\x84\x00\x00\x00\x00\xf0\x9f\x98\x80")
    #     self.assertFrameReceived(
    #         server,
    #         Frame(OP_TEXT, "😀".encode()),
    #     )
    #
    # def test_client_sends_fragmented_text(self):
    #     client = Protocol(CLIENT)
    #     with self.enforce_mask(b"\x00\x00\x00\x00"):
    #         client.send_text("😀".encode()[:2], fin=False)
    #     self.assertEqual(client.data_to_send(), [b"\x01\x82\x00\x00\x00\x00\xf0\x9f"])
    #     with self.enforce_mask(b"\x00\x00\x00\x00"):
    #         client.send_continuation("😀😀".encode()[2:6], fin=False)
    #     self.assertEqual(
    #         client.data_to_send(), [b"\x00\x84\x00\x00\x00\x00\x98\x80\xf0\x9f"]
    #     )
    #     with self.enforce_mask(b"\x00\x00\x00\x00"):
    #         client.send_continuation("😀".encode()[2:], fin=True)
    #     self.assertEqual(client.data_to_send(), [b"\x80\x82\x00\x00\x00\x00\x98\x80"])
    #
    # def test_server_sends_fragmented_text(self):
    #     server = Protocol(SERVER)
    #     server.send_text("😀".encode()[:2], fin=False)
    #     self.assertEqual(server.data_to_send(), [b"\x01\x02\xf0\x9f"])
    #     server.send_continuation("😀😀".encode()[2:6], fin=False)
    #     self.assertEqual(server.data_to_send(), [b"\x00\x04\x98\x80\xf0\x9f"])
    #     server.send_continuation("😀".encode()[2:], fin=True)
    #     self.assertEqual(server.data_to_send(), [b"\x80\x02\x98\x80"])
    #
    # def test_client_receives_fragmented_text(self):
    #     client = Protocol(CLIENT)
    #     client.receive_data(b"\x01\x02\xf0\x9f")
    #     self.assertFrameReceived(
    #         client,
    #         Frame(OP_TEXT, "😀".encode()[:2], fin=False),
    #     )
    #     client.receive_data(b"\x00\x04\x98\x80\xf0\x9f")
    #     self.assertFrameReceived(
    #         client,
    #         Frame(OP_CONT, "😀😀".encode()[2:6], fin=False),
    #     )
    #     client.receive_data(b"\x80\x02\x98\x80")
    #     self.assertFrameReceived(
    #         client,
    #         Frame(OP_CONT, "😀".encode()[2:]),
    #     )
    #
    # def test_server_receives_fragmented_text(self):
    #     server = Protocol(SERVER)
    #     server.receive_data(b"\x01\x82\x00\x00\x00\x00\xf0\x9f")
    #     self.assertFrameReceived(
    #         server,
    #         Frame(OP_TEXT, "😀".encode()[:2], fin=False),
    #     )
    #     server.receive_data(b"\x00\x84\x00\x00\x00\x00\x98\x80\xf0\x9f")
    #     self.assertFrameReceived(
    #         server,
    #         Frame(OP_CONT, "😀😀".encode()[2:6], fin=False),
    #     )
    #     server.receive_data(b"\x80\x82\x00\x00\x00\x00\x98\x80")
    #     self.assertFrameReceived(
    #         server,
    #         Frame(OP_CONT, "😀".encode()[2:]),
    #     )
    #
    # def test_client_receives_fragmented_text_over_size_limit(self):
    #     client = Protocol(CLIENT, max_size=3)
    #     client.receive_data(b"\x01\x02\xf0\x9f")
    #     self.assertFrameReceived(
    #         client,
    #         Frame(OP_TEXT, "😀".encode()[:2], fin=False),
    #     )
    #     client.receive_data(b"\x80\x02\x98\x80")
    #     self.assertIsInstance(client.parser_exc, PayloadTooBig)
    #     self.assertEqual(str(client.parser_exc), "over size limit (2 > 1 bytes)")
    #     self.assertConnectionFailing(
    #         client, CloseCode.MESSAGE_TOO_BIG, "over size limit (2 > 1 bytes)"
    #     )
    #
    # def test_server_receives_fragmented_text_over_size_limit(self):
    #     server = Protocol(SERVER, max_size=3)
    #     server.receive_data(b"\x01\x82\x00\x00\x00\x00\xf0\x9f")
    #     self.assertFrameReceived(
    #         server,
    #         Frame(OP_TEXT, "😀".encode()[:2], fin=False),
    #     )
    #     server.receive_data(b"\x80\x82\x00\x00\x00\x00\x98\x80")
    #     self.assertIsInstance(server.parser_exc, PayloadTooBig)
    #     self.assertEqual(str(server.parser_exc), "over size limit (2 > 1 bytes)")
    #     self.assertConnectionFailing(
    #         server, CloseCode.MESSAGE_TOO_BIG, "over size limit (2 > 1 bytes)"
    #     )
    #
    # def test_client_receives_fragmented_text_without_size_limit(self):
    #     client = Protocol(CLIENT, max_size=None)
    #     client.receive_data(b"\x01\x02\xf0\x9f")
    #     self.assertFrameReceived(
    #         client,
    #         Frame(OP_TEXT, "😀".encode()[:2], fin=False),
    #     )
    #     client.receive_data(b"\x00\x04\x98\x80\xf0\x9f")
    #     self.assertFrameReceived(
    #         client,
    #         Frame(OP_CONT, "😀😀".encode()[2:6], fin=False),
    #     )
    #     client.receive_data(b"\x80\x02\x98\x80")
    #     self.assertFrameReceived(
    #         client,
    #         Frame(OP_CONT, "😀".encode()[2:]),
    #     )
    #
    # def test_server_receives_fragmented_text_without_size_limit(self):
    #     server = Protocol(SERVER, max_size=None)
    #     server.receive_data(b"\x01\x82\x00\x00\x00\x00\xf0\x9f")
    #     self.assertFrameReceived(
    #         server,
    #         Frame(OP_TEXT, "😀".encode()[:2], fin=False),
    #     )
    #     server.receive_data(b"\x00\x84\x00\x00\x00\x00\x98\x80\xf0\x9f")
    #     self.assertFrameReceived(
    #         server,
    #         Frame(OP_CONT, "😀😀".encode()[2:6], fin=False),
    #     )
    #     server.receive_data(b"\x80\x82\x00\x00\x00\x00\x98\x80")
    #     self.assertFrameReceived(
    #         server,
    #         Frame(OP_CONT, "😀".encode()[2:]),
    #     )
    #
    # def test_client_sends_unexpected_text(self):
    #     client = Protocol(CLIENT)
    #     client.send_text(b"", fin=False)
    #     with self.assertRaises(ProtocolError) as raised:
    #         client.send_text(b"", fin=False)
    #     self.assertEqual(str(raised.exception), "expected a continuation frame")
    #
    # def test_server_sends_unexpected_text(self):
    #     server = Protocol(SERVER)
    #     server.send_text(b"", fin=False)
    #     with self.assertRaises(ProtocolError) as raised:
    #         server.send_text(b"", fin=False)
    #     self.assertEqual(str(raised.exception), "expected a continuation frame")
    #
    # def test_client_receives_unexpected_text(self):
    #     client = Protocol(CLIENT)
    #     client.receive_data(b"\x01\x00")
    #     self.assertFrameReceived(
    #         client,
    #         Frame(OP_TEXT, b"", fin=False),
    #     )
    #     client.receive_data(b"\x01\x00")
    #     self.assertIsInstance(client.parser_exc, ProtocolError)
    #     self.assertEqual(str(client.parser_exc), "expected a continuation frame")
    #     self.assertConnectionFailing(
    #         client, CloseCode.PROTOCOL_ERROR, "expected a continuation frame"
    #     )
    #
    # def test_server_receives_unexpected_text(self):
    #     server = Protocol(SERVER)
    #     server.receive_data(b"\x01\x80\x00\x00\x00\x00")
    #     self.assertFrameReceived(
    #         server,
    #         Frame(OP_TEXT, b"", fin=False),
    #     )
    #     server.receive_data(b"\x01\x80\x00\x00\x00\x00")
    #     self.assertIsInstance(server.parser_exc, ProtocolError)
    #     self.assertEqual(str(server.parser_exc), "expected a continuation frame")
    #     self.assertConnectionFailing(
    #         server, CloseCode.PROTOCOL_ERROR, "expected a continuation frame"
    #     )
    #
    # def test_client_sends_text_after_sending_close(self):
    #     client = Protocol(CLIENT)
    #     with self.enforce_mask(b"\x00\x00\x00\x00"):
    #         client.send_close(CloseCode.GOING_AWAY)
    #     self.assertEqual(client.data_to_send(), [b"\x88\x82\x00\x00\x00\x00\x03\xe9"])
    #     with self.assertRaises(InvalidState) as raised:
    #         client.send_text(b"")
    #     self.assertEqual(str(raised.exception), "connection is closing")
    #
    # def test_server_sends_text_after_sending_close(self):
    #     server = Protocol(SERVER)
    #     server.send_close(CloseCode.NORMAL_CLOSURE)
    #     self.assertEqual(server.data_to_send(), [b"\x88\x02\x03\xe8"])
    #     with self.assertRaises(InvalidState) as raised:
    #         server.send_text(b"")
    #     self.assertEqual(str(raised.exception), "connection is closing")
    #
    # def test_client_receives_text_after_receiving_close(self):
    #     client = Protocol(CLIENT)
    #     client.receive_data(b"\x88\x02\x03\xe8")
    #     self.assertConnectionClosing(client, CloseCode.NORMAL_CLOSURE)
    #     client.receive_data(b"\x81\x00")
    #     self.assertFrameReceived(client, None)
    #     self.assertFrameSent(client, None)
    #
    # def test_server_receives_text_after_receiving_close(self):
    #     server = Protocol(SERVER)
    #     server.receive_data(b"\x88\x82\x00\x00\x00\x00\x03\xe9")
    #     self.assertConnectionClosing(server, CloseCode.GOING_AWAY)
    #     server.receive_data(b"\x81\x80\x00\xff\x00\xff")
    #     self.assertFrameReceived(server, None)
    #     self.assertFrameSent(server, None)
