from testing import assert_equal, assert_raises, assert_true
from collections import Optional
from memory import UnsafePointer

from testutils import enforce_mask
from websockets.aliases import Bytes
from websockets.frames import (
    Close,
    Frame,
    CLOSE_CODE_GOING_AWAY,
    # CLOSE_CODE_MESSAGE_TOO_BIG,
    CLOSE_CODE_NORMAL_CLOSURE,
    CLOSE_CODE_PROTOCOL_ERROR,
    OP_BINARY,
    OP_CONT,
    OP_TEXT,
    OP_CLOSE,
)
from websockets.protocol import Event, CLIENT, SERVER, OPEN
from websockets.protocol.base import (
    receive_data, 
    send_binary,
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
    """Protocol struct for testing purposes."""
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
    var expect_cont_frame: Bool

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
        self.expect_cont_frame = False

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
        return self.expect_cont_frame

    fn set_expect_continuation_frame(mut self, value: Bool) -> None:
        """Set the expectation of a continuation frame."""
        self.expect_cont_frame = value

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


# ===-------------------------------------------------------------------===#
# Test frame masking.
# ===-------------------------------------------------------------------===#


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


# ===-------------------------------------------------------------------===#
# Test continuation frames without text or binary frames.
# ===-------------------------------------------------------------------===#


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


# ===-------------------------------------------------------------------===#
# Test text frames and continuation frames.
# ===-------------------------------------------------------------------===#


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


# TODO: Implement the max_size in the protocol
# fn test_client_receives_text_over_size_limit() raises:
#     client = DummyProtocol[False, CLIENT, max_size=3](OPEN, StreamReader(), Bytes(), List[Event]())
#     
#     # Send a 4-byte text frame containing '😀' (240, 159, 152, 128)
#     receive_data(client, Bytes(129, 4, 240, 159, 152, 128))
#     
#     events = client.events_received()
#     assert_equal(client.parser_exc.value()._message(), "PayloadTooBig: over size limit (4 > 3 bytes)")
#     assert_equal(events[0][Frame], Frame(OP_CLOSE, Close(CLOSE_CODE_MESSAGE_TOO_BIG, "over size limit (4 > 3 bytes)").serialize(), fin=True))

# TODO: Implement the max_size in the protocol
# fn test_server_receives_text_over_size_limit() raises:
#     server = DummyProtocol[True, SERVER, max_size=3](OPEN, StreamReader(), Bytes(), List[Event]())
#     
#     # Send a 4-byte text frame containing '😀' (240, 159, 152, 128)
#     receive_data(server, Bytes(129, 132, 0, 0, 0, 0, 240, 159, 152, 128))
#     
#     events = server.events_received()
#     assert_equal(server.parser_exc.value()._message(), "PayloadTooBig: over size limit (4 > 3 bytes)")
#     assert_equal(events[0][Frame], Frame(OP_CLOSE, Close(CLOSE_CODE_MESSAGE_TOO_BIG, "over size limit (4 > 3 bytes)").serialize(), fin=True))

fn test_client_sends_fragmented_text() raises:
    """The test verifies that a client can properly fragment and send a text message containing emoji data across multiple frames with proper masking."""
    client = DummyProtocol[True, CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    fn gen_mask() -> Bytes:
        return Bytes(0, 0, 0, 0)
    
    # First fragment
    send_text[gen_mask_func=gen_mask](client, smiley_data[:2], fin=False)
    assert_equal(client.data_to_send(), Bytes(1, 130, 0, 0, 0, 0, 240, 159))
    
    # Second fragment
    send_continuation[gen_mask_func=gen_mask](client, smiley_data[2:] + smiley_data[:2], fin=False)
    assert_equal(client.data_to_send(), Bytes(0, 132, 0, 0, 0, 0, 152, 128, 240, 159))
    
    # Final fragment
    send_continuation[gen_mask_func=gen_mask](client, smiley_data[2:], fin=True)
    assert_equal(client.data_to_send(), Bytes(128, 130, 0, 0, 0, 0, 152, 128))


fn test_server_sends_fragmented_text() raises:
    """The test verifies that a server can properly fragment and send a text message containing emoji data across multiple frames."""
    server = DummyProtocol[False, SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    
    # First fragment
    send_text(server, smiley_data[:2], fin=False)
    assert_equal(server.data_to_send(), Bytes(1, 2, 240, 159))
    
    # Second fragment 
    send_continuation(server, smiley_data[2:] + smiley_data[:2], fin=False)
    assert_equal(server.data_to_send(), Bytes(0, 4, 152, 128, 240, 159))
    
    # Final fragment
    send_continuation(server, smiley_data[2:], fin=True)
    assert_equal(server.data_to_send(), Bytes(128, 2, 152, 128))


fn test_client_receives_fragmented_text() raises:
    """The test verifies that a client can properly receive fragmented text messages containing emoji data."""
    client = DummyProtocol[False, CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    
    # First fragment
    receive_data(client, Bytes(1, 2, 240, 159))
    events = client.events_received()
    assert_equal(events[0][Frame], Frame(OP_TEXT, smiley_data[:2], fin=False))
    
    # Second fragment
    receive_data(client, Bytes(0, 4, 152, 128, 240, 159))
    events = client.events_received()
    assert_equal(events[0][Frame], Frame(OP_CONT, smiley_data[2:] + smiley_data[:2], fin=False))
    
    # Final fragment
    receive_data(client, Bytes(128, 2, 152, 128))
    events = client.events_received()
    assert_equal(events[0][Frame], Frame(OP_CONT, smiley_data[2:]))


fn test_server_receives_fragmented_text() raises:
    """The test verifies that a server can properly receive fragmented text messages containing emoji data."""
    server = DummyProtocol[True, SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    
    # First fragment
    receive_data(server, Bytes(1, 130, 0, 0, 0, 0, 240, 159))
    events = server.events_received()
    assert_equal(events[0][Frame], Frame(OP_TEXT, smiley_data[:2], fin=False))
    
    # Second fragment
    receive_data(server, Bytes(0, 132, 0, 0, 0, 0, 152, 128, 240, 159))
    events = server.events_received()
    assert_equal(events[0][Frame], Frame(OP_CONT, smiley_data[2:] + smiley_data[:2], fin=False))
    
    # Final fragment
    receive_data(server, Bytes(128, 130, 0, 0, 0, 0, 152, 128))
    events = server.events_received()
    assert_equal(events[0][Frame], Frame(OP_CONT, smiley_data[2:]))

# TODO: Implement the max_size in the protocol
# fn test_client_receives_fragmented_text_over_size_limit() raises:
#     """The test verifies that a client properly handles fragmented text messages that exceed the size limit."""
#     client = DummyProtocol[False, CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
#     
#     # First fragment
#     receive_data(client, Bytes(1, 2, 240, 159))
#     events = client.events_received()
#     assert_equal(events[0][Frame], Frame(OP_TEXT, smiley_data[:2], fin=False))
#     
#     # Second fragment exceeds size limit
#     receive_data(client, Bytes(128, 2, 152, 128))
#     events = client.events_received()
#     assert_equal(client.parser_exc.value()._message(), "PayloadTooBig: over size limit (2 > 1 bytes)")
#     assert_equal(events[0][Frame], Frame(OP_CLOSE, Close(CLOSE_CODE_MESSAGE_TOO_BIG, "over size limit (2 > 1 bytes)").serialize(), fin=True))

# TODO: Implement the max_size in the protocol
# fn test_server_receives_fragmented_text_over_size_limit() raises:
#     """The test verifies that a server properly handles fragmented text messages that exceed the size limit."""
#     server = DummyProtocol[True, SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
#     
#     # First fragment
#     receive_data(server, Bytes(1, 130, 0, 0, 0, 0, 240, 159))
#     events = server.events_received()
#     assert_equal(events[0][Frame], Frame(OP_TEXT, smiley_data[:2], fin=False))
#     
#     # Second fragment exceeds size limit
#     receive_data(server, Bytes(128, 130, 0, 0, 0, 0, 152, 128))
#     events = server.events_received()
#     assert_equal(server.parser_exc.value()._message(), "PayloadTooBig: over size limit (2 > 1 bytes)")
#     assert_equal(events[0][Frame], Frame(OP_CLOSE, Close(CLOSE_CODE_MESSAGE_TOO_BIG, "over size limit (2 > 1 bytes)").serialize(), fin=True))


fn test_client_sends_unexpected_text() raises:
    """The test verifies that a client cannot send a text frame after sending a text frame without the FIN bit set."""
    client = DummyProtocol[True, CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    fn gen_mask() -> Bytes:
        return Bytes(0, 0, 0, 0)
    send_text[gen_mask_func=gen_mask](client, Bytes(), fin=False)
    with assert_raises(contains="ProtocolError: expected a continuation frame"):
        send_text[gen_mask_func=gen_mask](client, Bytes(), fin=False)


fn test_server_sends_unexpected_text() raises:
    """The test verifies that a server cannot send a text frame after sending a text frame without the FIN bit set."""
    server = DummyProtocol[False, SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    send_text(server, Bytes(), fin=False)
    with assert_raises(contains="ProtocolError: expected a continuation frame"):
        send_text(server, Bytes(), fin=False)


fn test_client_receives_unexpected_text() raises:
    """The test verifies that a client properly handles receiving an unexpected text frame."""
    client = DummyProtocol[False, CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    
    # First text frame without FIN bit
    receive_data(client, Bytes(1, 0))
    events = client.events_received()
    assert_equal(events[0][Frame], Frame(OP_TEXT, Bytes(), fin=False))
    
    # Second unexpected text frame
    receive_data(client, Bytes(1, 0))
    events = client.events_received()
    assert_equal(client.parser_exc.value()._message(), "ProtocolError: expected a continuation frame")
    assert_equal(events[0][Frame], Frame(OP_CLOSE, Close(CLOSE_CODE_PROTOCOL_ERROR, "ProtocolError: expected a continuation frame").serialize(), fin=True))

fn test_server_receives_unexpected_text() raises:
    """The test verifies that a server properly handles receiving an unexpected text frame."""
    server = DummyProtocol[True, SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    
    # First text frame without FIN bit
    receive_data(server, Bytes(1, 128, 0, 0, 0, 0))
    events = server.events_received()
    assert_equal(events[0][Frame], Frame(OP_TEXT, Bytes(), fin=False))
    
    # Second unexpected text frame
    receive_data(server, Bytes(1, 128, 0, 0, 0, 0))
    events = server.events_received()
    assert_equal(server.parser_exc.value()._message(), "ProtocolError: expected a continuation frame")
    assert_equal(events[0][Frame], Frame(OP_CLOSE, Close(CLOSE_CODE_PROTOCOL_ERROR, "ProtocolError: expected a continuation frame").serialize(), fin=True))


fn test_client_sends_text_after_sending_close() raises:
    """The test verifies that a client cannot send text frames after sending a close frame."""
    client = DummyProtocol[True, CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    fn gen_mask() -> Bytes:
        return Bytes(0, 0, 0, 0)
    send_close[gen_mask_func=gen_mask](client, CLOSE_CODE_GOING_AWAY)
    assert_equal(client.data_to_send(), Bytes(136, 130, 0, 0, 0, 0, 3, 233))
    with assert_raises(contains="InvalidState: connection is 2"):
        send_text[gen_mask_func=gen_mask](client, Bytes())


fn test_server_sends_text_after_sending_close() raises:
    """The test verifies that a server cannot send text frames after sending a close frame."""
    server = DummyProtocol[False, SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    send_close(server, CLOSE_CODE_NORMAL_CLOSURE)
    assert_equal(server.data_to_send(), Bytes(136, 2, 3, 232))
    with assert_raises(contains="InvalidState: connection is 2"):
        send_text(server, Bytes())


fn test_client_receives_text_after_receiving_close() raises:
    """The test verifies that a client properly ignores text frames after receiving a close frame."""
    client = DummyProtocol[False, CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    
    # Receive close frame
    receive_data(client, Bytes(136, 2, 3, 232))
    events = client.events_received()
    close_frame = Frame(OP_CLOSE, Close(CLOSE_CODE_NORMAL_CLOSURE, "").serialize(), fin=True)
    assert_equal(events[0][Frame], close_frame)
    assert_equal(client.data_to_send(), close_frame.serialize[gen_mask_func=gen_mask](mask=client.is_masked()))
    
    # Receive text frame after close
    receive_data(client, Bytes(129, 0))
    events = client.events_received()
    assert_equal(len(events), 0)
    assert_equal(client.data_to_send(), Bytes())


fn test_server_receives_text_after_receiving_close() raises:
    """The test verifies that a server properly ignores text frames after receiving a close frame."""
    server = DummyProtocol[True, SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    
    fn gen_mask() -> Bytes:
        return Bytes(0, 0, 0, 0)
    # Receive close frame
    receive_data[gen_mask_func=gen_mask](server, Bytes(136, 130, 0, 0, 0, 0, 3, 233))
    events = server.events_received()
    close_frame = Frame(OP_CLOSE, Close(CLOSE_CODE_GOING_AWAY, "").serialize(), fin=True)
    assert_equal(events[0][Frame], close_frame)
    assert_equal(server.data_to_send(), close_frame.serialize[gen_mask_func=gen_mask](mask=server.is_masked()))
    
    # Receive text frame after close
    receive_data(server, Bytes(129, 128, 0, 255, 0, 255))
    events = server.events_received()
    assert_equal(len(events), 0)
    assert_equal(server.data_to_send(), Bytes())


# ===-------------------------------------------------------------------===#
# Test binary frames and continuation frames.
# ===-------------------------------------------------------------------===#


fn test_client_sends_binary() raises:
    """The test verifies that a client can properly send binary data with masking."""
    client = DummyProtocol[True, CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    fn gen_mask() -> Bytes:
        return Bytes(0, 0, 0, 0)
    send_binary[gen_mask_func=gen_mask](client, Bytes(1, 2, 254, 255))
    assert_equal(client.data_to_send(), Bytes(130, 132, 0, 0, 0, 0, 1, 2, 254, 255))


fn test_server_sends_binary() raises:
    """The test verifies that a server can properly send binary data without masking."""
    server = DummyProtocol[False, SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    send_binary(server, Bytes(1, 2, 254, 255))
    assert_equal(server.data_to_send(), Bytes(130, 4, 1, 2, 254, 255))


fn test_client_receives_binary() raises:
    """The test verifies that a client can properly receive binary data."""
    client = DummyProtocol[False, CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data(client, Bytes(130, 4, 1, 2, 254, 255))
    events = client.events_received()
    assert_equal(events[0][Frame], Frame(OP_BINARY, Bytes(1, 2, 254, 255)))


fn test_server_receives_binary() raises:
    """The test verifies that a server can properly receive binary data."""
    server = DummyProtocol[True, SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data(server, Bytes(130, 132, 0, 0, 0, 0, 1, 2, 254, 255))
    events = server.events_received()
    assert_equal(events[0][Frame], Frame(OP_BINARY, Bytes(1, 2, 254, 255)))


# TODO: Implement the max_size in the protocol
# fn test_client_receives_binary_over_size_limit() raises:
#     """The test verifies that a client properly handles binary data exceeding size limits."""
#     client = DummyProtocol[False, CLIENT, max_size=3](OPEN, StreamReader(), Bytes(), List[Event]())
#     receive_data(client, Bytes(130, 4, 1, 2, 254, 255))
#     assert_equal(client.parser_exc.value()._message(), "PayloadTooBig: over size limit (4 > 3 bytes)")
#     assert_equal(events[0][Frame], Frame(OP_CLOSE, Close(CLOSE_CODE_MESSAGE_TOO_BIG, "over size limit (4 > 3 bytes)").serialize(), fin=True))

# TODO: Implement the max_size in the protocol
# fn test_server_receives_binary_over_size_limit() raises:
#     """The test verifies that a server properly handles binary data exceeding size limits."""
#     server = DummyProtocol[True, SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
#     receive_data(server, Bytes(130, 132, 0, 0, 0, 0, 1, 2, 254, 255))
#     events = server.events_received()
#     assert_equal(server.parser_exc.value()._message(), "PayloadTooBig: over size limit (4 > 3 bytes)")
#     assert_equal(events[0][Frame], Frame(OP_CLOSE, Close(CLOSE_CODE_MESSAGE_TOO_BIG, "over size limit (4 > 3 bytes)").serialize(), fin=True))


fn test_client_sends_fragmented_binary() raises:
    """The test verifies that a client can properly fragment and send binary data with masking."""
    client = DummyProtocol[True, CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    fn gen_mask() -> Bytes:
        return Bytes(0, 0, 0, 0)
    
    # First fragment
    send_binary[gen_mask_func=gen_mask](client, Bytes(1, 2), fin=False)
    assert_equal(client.data_to_send(), Bytes(2, 130, 0, 0, 0, 0, 1, 2))
    
    # Second fragment
    send_continuation[gen_mask_func=gen_mask](client, Bytes(238, 255, 1, 2), fin=False)
    assert_equal(client.data_to_send(), Bytes(0, 132, 0, 0, 0, 0, 238, 255, 1, 2))
    
    # Final fragment
    send_continuation[gen_mask_func=gen_mask](client, Bytes(238, 255), fin=True)
    assert_equal(client.data_to_send(), Bytes(128, 130, 0, 0, 0, 0, 238, 255))


fn test_server_sends_fragmented_binary() raises:
    """The test verifies that a server can properly fragment and send binary data without masking."""
    server = DummyProtocol[False, SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    
    # First fragment
    send_binary(server, Bytes(1, 2), fin=False)
    assert_equal(server.data_to_send(), Bytes(2, 2, 1, 2))
    
    # Second fragment
    send_continuation(server, Bytes(238, 255, 1, 2), fin=False)
    assert_equal(server.data_to_send(), Bytes(0, 4, 238, 255, 1, 2))
    
    # Final fragment
    send_continuation(server, Bytes(238, 255), fin=True)
    assert_equal(server.data_to_send(), Bytes(128, 2, 238, 255))


fn test_client_receives_fragmented_binary() raises:
    """The test verifies that a client can properly receive fragmented binary data."""
    client = DummyProtocol[False, CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    
    # First fragment
    receive_data(client, Bytes(2, 2, 1, 2))
    events = client.events_received()
    assert_equal(events[0][Frame], Frame(OP_BINARY, Bytes(1, 2), fin=False))
    
    # Second fragment
    receive_data(client, Bytes(0, 4, 254, 255, 1, 2))
    events = client.events_received()
    assert_equal(events[0][Frame], Frame(OP_CONT, Bytes(254, 255, 1, 2), fin=False))
    
    # Final fragment
    receive_data(client, Bytes(128, 2, 254, 255))
    events = client.events_received()
    assert_equal(events[0][Frame], Frame(OP_CONT, Bytes(254, 255)))


fn test_server_receives_fragmented_binary() raises:
    """The test verifies that a server can properly receive fragmented binary data."""
    server = DummyProtocol[True, SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    
    # First fragment
    receive_data(server, Bytes(2, 130, 0, 0, 0, 0, 1, 2))
    events = server.events_received()
    assert_equal(events[0][Frame], Frame(OP_BINARY, Bytes(1, 2), fin=False))
    
    # Second fragment
    receive_data(server, Bytes(0, 132, 0, 0, 0, 0, 238, 255, 1, 2))
    events = server.events_received()
    assert_equal(events[0][Frame], Frame(OP_CONT, Bytes(238, 255, 1, 2), fin=False))
    
    # Final fragment
    receive_data(server, Bytes(128, 130, 0, 0, 0, 0, 254, 255))
    events = server.events_received()
    assert_equal(events[0][Frame], Frame(OP_CONT, Bytes(254, 255)))


# TODO: Implement the max_size in the protocol
# fn test_client_receives_fragmented_binary_over_size_limit() raises:
#     """The test verifies that a client properly handles fragmented binary data exceeding size limits."""
#     client = DummyProtocol[False, CLIENT, max_size=3](OPEN, StreamReader(), Bytes(), List[Event]())
#     
#     # First fragment
#     receive_data(client, Bytes(2, 2, 1, 2))
#     events = client.events_received()
#     assert_equal(events[0][Frame], Frame(OP_BINARY, Bytes(1, 2), fin=False))
#     
#     # Second fragment exceeds size limit
#     receive_data(client, Bytes(128, 2, 254, 255))
#     events = client.events_received()
#     assert_equal(client.parser_exc.value()._message(), "PayloadTooBig: over size limit (2 > 1 bytes)")
#     assert_equal(events[0][Frame], Frame(OP_CLOSE, Close(CLOSE_CODE_MESSAGE_TOO_BIG, "over size limit (2 > 1 bytes)").serialize(), fin=True))

# TODO: Implement the max_size in the protocol
# fn test_server_receives_fragmented_binary_over_size_limit() raises:
#     """The test verifies that a server properly handles fragmented binary data exceeding size limits."""
#     server = DummyProtocol[True, SERVER, max_size=3](OPEN, StreamReader(), Bytes(), List[Event]())
#     
#     # First fragment
#     receive_data(server, Bytes(2, 130, 0, 0, 0, 0, 1, 2))
#     events = server.events_received()
#     assert_equal(events[0][Frame], Frame(OP_BINARY, Bytes(1, 2), fin=False))
#     
#     # Second fragment exceeds size limit
#     receive_data(server, Bytes(128, 130, 0, 0, 0, 0, 254, 255))
#     events = server.events_received()
#     assert_equal(server.parser_exc.value()._message(), "PayloadTooBig: over size limit (2 > 1 bytes)")
#     assert_equal(events[0][Frame], Frame(OP_CLOSE, Close(CLOSE_CODE_MESSAGE_TOO_BIG, "over size limit (2 > 1 bytes)").serialize(), fin=True))
#

fn test_client_sends_unexpected_binary() raises:
    """The test verifies that a client cannot send a binary frame after sending a binary frame without the FIN bit set."""
    client = DummyProtocol[True, CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    fn gen_mask() -> Bytes:
        return Bytes(0, 0, 0, 0)
    send_binary[gen_mask_func=gen_mask](client, Bytes(), fin=False)
    with assert_raises(contains="ProtocolError: expected a continuation frame"):
        send_binary[gen_mask_func=gen_mask](client, Bytes(), fin=False)


fn test_server_sends_unexpected_binary() raises:
    """The test verifies that a server cannot send a binary frame after sending a binary frame without the FIN bit set."""
    server = DummyProtocol[False, SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    send_binary(server, Bytes(), fin=False)
    with assert_raises(contains="ProtocolError: expected a continuation frame"):
        send_binary(server, Bytes(), fin=False)


fn test_client_receives_unexpected_binary() raises:
    """The test verifies that a client properly handles receiving an unexpected binary frame."""
    client = DummyProtocol[False, CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    
    # First binary frame without FIN bit
    receive_data(client, Bytes(2, 0))
    events = client.events_received()
    assert_equal(events[0][Frame], Frame(OP_BINARY, Bytes(), fin=False))
    
    # Second unexpected binary frame
    receive_data(client, Bytes(2, 0))
    events = client.events_received()
    assert_equal(client.parser_exc.value()._message(), "ProtocolError: expected a continuation frame")
    assert_equal(events[0][Frame], Frame(OP_CLOSE, Close(CLOSE_CODE_PROTOCOL_ERROR, "ProtocolError: expected a continuation frame").serialize(), fin=True))


fn test_server_receives_unexpected_binary() raises:
    """The test verifies that a server properly handles receiving an unexpected binary frame."""
    server = DummyProtocol[True, SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    
    # First binary frame without FIN bit
    receive_data(server, Bytes(2, 128, 0, 0, 0, 0))
    events = server.events_received()
    assert_equal(events[0][Frame], Frame(OP_BINARY, Bytes(), fin=False))
    
    # Second unexpected binary frame
    receive_data(server, Bytes(2, 128, 0, 0, 0, 0))
    events = server.events_received()
    assert_equal(server.get_parser_exc().value()._message(), "ProtocolError: expected a continuation frame")
    assert_equal(events[0][Frame], Frame(OP_CLOSE, Close(CLOSE_CODE_PROTOCOL_ERROR, "ProtocolError: expected a continuation frame").serialize(), fin=True))


fn test_client_sends_binary_after_sending_close() raises:
    """The test verifies that a client cannot send binary frames after sending a close frame."""
    client = DummyProtocol[True, CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    fn gen_mask() -> Bytes:
        return Bytes(0, 0, 0, 0)
    send_close[gen_mask_func=gen_mask](client, CLOSE_CODE_GOING_AWAY)
    assert_equal(client.data_to_send(), Bytes(136, 130, 0, 0, 0, 0, 3, 233))
    with assert_raises(contains="InvalidState: connection is 2"):
        send_binary[gen_mask_func=gen_mask](client, Bytes())


fn test_server_sends_binary_after_sending_close() raises:
    """The test verifies that a server cannot send binary frames after sending a close frame."""
    server = DummyProtocol[False, SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    send_close(server, CLOSE_CODE_NORMAL_CLOSURE)
    assert_equal(server.data_to_send(), Bytes(136, 2, 3, 232))
    with assert_raises(contains="InvalidState: connection is 2"):
        send_binary(server, Bytes())


fn test_client_receives_binary_after_receiving_close() raises:
    """The test verifies that a client properly ignores binary frames after receiving a close frame."""
    client = DummyProtocol[False, CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    
    # Receive close frame
    receive_data(client, Bytes(136, 2, 3, 232))
    events = client.events_received()
    close_frame = Frame(OP_CLOSE, Close(CLOSE_CODE_NORMAL_CLOSURE, "").serialize(), fin=True)
    assert_equal(events[0][Frame], close_frame)
    assert_equal(client.data_to_send(), close_frame.serialize[gen_mask_func=gen_mask](mask=client.is_masked()))
    
    # Receive binary frame after close
    receive_data(client, Bytes(130, 0))
    events = client.events_received()
    assert_equal(len(events), 0)
    assert_equal(client.data_to_send(), Bytes())


fn test_server_receives_binary_after_receiving_close() raises:
    """The test verifies that a server properly ignores binary frames after receiving a close frame."""
    server = DummyProtocol[True, SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    
    fn gen_mask() -> Bytes:
        return Bytes(0, 0, 0, 0)
    # Receive close frame
    receive_data[gen_mask_func=gen_mask](server, Bytes(136, 130, 0, 0, 0, 0, 3, 233))
    events = server.events_received()
    close_frame = Frame(OP_CLOSE, Close(CLOSE_CODE_GOING_AWAY, "").serialize(), fin=True)
    assert_equal(events[0][Frame], close_frame)
    assert_equal(server.data_to_send(), close_frame.serialize[gen_mask_func=gen_mask](mask=server.is_masked()))
    
    # Receive binary frame after close
    receive_data(server, Bytes(130, 128, 0, 255, 0, 255))
    events = server.events_received()
    assert_equal(len(events), 0)
    assert_equal(server.data_to_send(), Bytes())


# ===-------------------------------------------------------------------===#
# Test close frames.
# ===-------------------------------------------------------------------===#


fn test_close_code() raises:
    """Test that close code is properly received and parsed."""
    client = DummyProtocol[False, CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data(client, Bytes(136, 4, 3, 232, 79, 75))  # \x88\x04\x03\xe8OK
    events = client.events_received()
    assert_equal(events[0][Frame], Frame(OP_CLOSE, Close(CLOSE_CODE_NORMAL_CLOSURE, "OK").serialize(), fin=True))


fn test_close_reason() raises:
    """Test that close reason is properly received and parsed."""
    server = DummyProtocol[True, SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    fn gen_mask() -> Bytes:
        return Bytes(0, 0, 0, 0)
    receive_data[gen_mask_func=gen_mask](server, Bytes(136, 132, 0, 0, 0, 0, 3, 232, 79, 75))  # \x88\x84\x00\x00\x00\x00\x03\xe8OK
    events = server.events_received()
    assert_equal(events[0][Frame], Frame(OP_CLOSE, Close(CLOSE_CODE_NORMAL_CLOSURE, "OK").serialize(), fin=True))


fn test_close_code_not_provided() raises:
    """Test handling when no close code is provided."""
    server = DummyProtocol[True, SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    fn gen_mask() -> Bytes:
        return Bytes(0, 0, 0, 0)
    receive_data[gen_mask_func=gen_mask](server, Bytes(136, 128, 0, 0, 0, 0))  # \x88\x80\x00\x00\x00\x00
    events = server.events_received()
    assert_equal(events[0][Frame], Frame(OP_CLOSE, Bytes(), fin=True))


fn test_close_reason_not_provided() raises:
    """Test handling when no close reason is provided."""
    client = DummyProtocol[False, CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data(client, Bytes(136, 0))  # \x88\x00
    events = client.events_received()
    assert_equal(events[0][Frame], Frame(OP_CLOSE, Bytes(), fin=True))


fn test_close_code_not_available() raises:
    """Test that close code is ABNORMAL_CLOSURE when connection is closed without a code."""
    client = DummyProtocol[False, CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    client.set_eof_sent(True)
    assert_equal(bool(client.get_close_rcvd()), False)


fn test_close_reason_not_available() raises:
    """Test that close reason is empty when connection is closed without a reason."""
    server = DummyProtocol[False, SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    server.set_eof_sent(True)
    assert_equal(bool(server.get_close_rcvd()), False)


fn test_close_code_not_available_yet() raises:
    """Test that close code is None before connection is closed."""
    server = DummyProtocol[False, SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    assert_equal(bool(server.get_close_rcvd()), False)


fn test_close_reason_not_available_yet() raises:
    """Test that close reason is None before connection is closed."""
    client = DummyProtocol[False, CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    assert_equal(bool(client.get_close_rcvd()), False)


fn test_client_sends_close() raises:
    """Test that client properly sends a close frame."""
    client = DummyProtocol[True, CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    fn gen_mask() -> Bytes:
        return Bytes(60, 60, 60, 60)  # \x3c\x3c\x3c\x3c
    send_close[gen_mask_func=gen_mask](client)
    assert_equal(client.data_to_send(), Bytes(136, 128, 60, 60, 60, 60))  # \x88\x80\x3c\x3c\x3c\x3c
    assert_equal(client.get_state(), 2)  # CLOSING


fn test_server_sends_close() raises:
    """Test that server properly sends a close frame."""
    server = DummyProtocol[False, SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    send_close(server)
    assert_equal(server.data_to_send(), Bytes(136, 0))  # \x88\x00
    assert_equal(server.get_state(), 2)  # CLOSING


fn test_client_receives_close() raises:
    """Test that client properly receives a close frame."""
    client = DummyProtocol[False, CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    fn gen_mask() -> Bytes:
        return Bytes(60, 60, 60, 60)  # \x3c\x3c\x3c\x3c
    receive_data[gen_mask_func=gen_mask](client, Bytes(136, 0))  # \x88\x00
    events = client.events_received()
    assert_equal(events[0][Frame], Frame(OP_CLOSE, Bytes(), fin=True))
    assert_equal(client.data_to_send(), Frame(OP_CLOSE, Bytes(), fin=True).serialize(mask=False))
    assert_equal(client.get_state(), 2)  # CLOSING


fn test_server_receives_close() raises:
    """Test that server properly receives a close frame."""
    server = DummyProtocol[True, SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    fn gen_mask() -> Bytes:
        return Bytes(60, 60, 60, 60)  # \x3c\x3c\x3c\x3c
    receive_data[gen_mask_func=gen_mask](server, Bytes(136, 128, 60, 60, 60, 60))  # \x88\x80\x3c\x3c\x3c\x3c
    events = server.events_received()
    assert_equal(events[0][Frame], Frame(OP_CLOSE, Bytes(), fin=True))
    assert_equal(server.data_to_send(), Frame(OP_CLOSE, Bytes(), fin=True).serialize[gen_mask_func=gen_mask](mask=True))
    assert_equal(server.get_state(), 2)  # CLOSING


fn test_client_sends_close_then_receives_close() raises:
    """Test client-initiated close handshake on the client side."""
    client = DummyProtocol[False, CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    
    send_close(client)
    events = client.events_received()
    assert_equal(len(events), 0)
    assert_equal(client.data_to_send(), Frame(OP_CLOSE, Bytes(), fin=True).serialize(mask=False))
    
    # Receive close
    receive_data[gen_mask_func=gen_mask](client, Bytes(136, 0))  # \x88\x00
    events = client.events_received()
    assert_equal(events[0][Frame], Frame(OP_CLOSE, Bytes(), fin=True))
    assert_equal(client.data_to_send(), Bytes())
    
    # Receive EOF
    client.set_eof_sent(True)
    events = client.events_received()
    assert_equal(len(events), 0)
    assert_equal(client.data_to_send(), Bytes())

#
# def test_server_sends_close_then_receives_close(self):
#     # Server-initiated close handshake on the server side.
#     server = Protocol(SERVER)
#
#     server.send_close()
#     self.assertFrameReceived(server, None)
#     self.assertFrameSent(server, Frame(OP_CLOSE, b""))
#
#     server.receive_data(b"\x88\x80\x3c\x3c\x3c\x3c")
#     self.assertFrameReceived(server, Frame(OP_CLOSE, b""))
#     self.assertFrameSent(server, None, eof=True)
#
#     server.receive_eof()
#     self.assertFrameReceived(server, None)
#     self.assertFrameSent(server, None)
#
# def test_client_receives_close_then_sends_close(self):
#     # Server-initiated close handshake on the client side.
#     client = Protocol(CLIENT)
#
#     client.receive_data(b"\x88\x00")
#     self.assertFrameReceived(client, Frame(OP_CLOSE, b""))
#     self.assertFrameSent(client, Frame(OP_CLOSE, b""))
#
#     client.receive_eof()
#     self.assertFrameReceived(client, None)
#     self.assertFrameSent(client, None, eof=True)
#
# def test_server_receives_close_then_sends_close(self):
#     # Client-initiated close handshake on the server side.
#     server = Protocol(SERVER)
#
#     server.receive_data(b"\x88\x80\x3c\x3c\x3c\x3c")
#     self.assertFrameReceived(server, Frame(OP_CLOSE, b""))
#     self.assertFrameSent(server, Frame(OP_CLOSE, b""), eof=True)
#
#     server.receive_eof()
#     self.assertFrameReceived(server, None)
#     self.assertFrameSent(server, None)
#
# def test_client_sends_close_with_code(self):
#     client = Protocol(CLIENT)
#     with self.enforce_mask(b"\x00\x00\x00\x00"):
#         client.send_close(CloseCode.GOING_AWAY)
#     self.assertEqual(client.data_to_send(), [b"\x88\x82\x00\x00\x00\x00\x03\xe9"])
#     self.assertIs(client.state, CLOSING)
#
# def test_server_sends_close_with_code(self):
#     server = Protocol(SERVER)
#     server.send_close(CloseCode.NORMAL_CLOSURE)
#     self.assertEqual(server.data_to_send(), [b"\x88\x02\x03\xe8"])
#     self.assertIs(server.state, CLOSING)
#
# def test_client_receives_close_with_code(self):
#     client = Protocol(CLIENT)
#     client.receive_data(b"\x88\x02\x03\xe8")
#     self.assertConnectionClosing(client, CloseCode.NORMAL_CLOSURE, "")
#     self.assertIs(client.state, CLOSING)
#
# def test_server_receives_close_with_code(self):
#     server = Protocol(SERVER)
#     server.receive_data(b"\x88\x82\x00\x00\x00\x00\x03\xe9")
#     self.assertConnectionClosing(server, CloseCode.GOING_AWAY, "")
#     self.assertIs(server.state, CLOSING)
#
# def test_client_sends_close_with_code_and_reason(self):
#     client = Protocol(CLIENT)
#     with self.enforce_mask(b"\x00\x00\x00\x00"):
#         client.send_close(CloseCode.GOING_AWAY, "going away")
#     self.assertEqual(
#         client.data_to_send(), [b"\x88\x8c\x00\x00\x00\x00\x03\xe9going away"]
#     )
#     self.assertIs(client.state, CLOSING)
#
# def test_server_sends_close_with_code_and_reason(self):
#     server = Protocol(SERVER)
#     server.send_close(CloseCode.NORMAL_CLOSURE, "OK")
#     self.assertEqual(server.data_to_send(), [b"\x88\x04\x03\xe8OK"])
#     self.assertIs(server.state, CLOSING)
#
# def test_client_receives_close_with_code_and_reason(self):
#     client = Protocol(CLIENT)
#     client.receive_data(b"\x88\x04\x03\xe8OK")
#     self.assertConnectionClosing(client, CloseCode.NORMAL_CLOSURE, "OK")
#     self.assertIs(client.state, CLOSING)
#
# def test_server_receives_close_with_code_and_reason(self):
#     server = Protocol(SERVER)
#     server.receive_data(b"\x88\x8c\x00\x00\x00\x00\x03\xe9going away")
#     self.assertConnectionClosing(server, CloseCode.GOING_AWAY, "going away")
#     self.assertIs(server.state, CLOSING)
#
# def test_client_sends_close_with_reason_only(self):
#     client = Protocol(CLIENT)
#     with self.assertRaises(ProtocolError) as raised:
#         client.send_close(reason="going away")
#     self.assertEqual(str(raised.exception), "cannot send a reason without a code")
#
# def test_server_sends_close_with_reason_only(self):
#     server = Protocol(SERVER)
#     with self.assertRaises(ProtocolError) as raised:
#         server.send_close(reason="OK")
#     self.assertEqual(str(raised.exception), "cannot send a reason without a code")
#
# def test_client_receives_close_with_truncated_code(self):
#     client = Protocol(CLIENT)
#     client.receive_data(b"\x88\x01\x03")
#     self.assertIsInstance(client.parser_exc, ProtocolError)
#     self.assertEqual(str(client.parser_exc), "close frame too short")
#     self.assertConnectionFailing(
#         client, CloseCode.PROTOCOL_ERROR, "close frame too short"
#     )
#     self.assertIs(client.state, CLOSING)
#
# def test_server_receives_close_with_truncated_code(self):
#     server = Protocol(SERVER)
#     server.receive_data(b"\x88\x81\x00\x00\x00\x00\x03")
#     self.assertIsInstance(server.parser_exc, ProtocolError)
#     self.assertEqual(str(server.parser_exc), "close frame too short")
#     self.assertConnectionFailing(
#         server, CloseCode.PROTOCOL_ERROR, "close frame too short"
#     )
#     self.assertIs(server.state, CLOSING)
#
# def test_client_receives_close_with_non_utf8_reason(self):
#     client = Protocol(CLIENT)
#
#     client.receive_data(b"\x88\x04\x03\xe8\xff\xff")
#     self.assertIsInstance(client.parser_exc, UnicodeDecodeError)
#     self.assertEqual(
#         str(client.parser_exc),
#         "'utf-8' codec can't decode byte 0xff in position 0: invalid start byte",
#     )
#     self.assertConnectionFailing(
#         client, CloseCode.INVALID_DATA, "invalid start byte at position 0"
#     )
#     self.assertIs(client.state, CLOSING)
#
# def test_server_receives_close_with_non_utf8_reason(self):
#     server = Protocol(SERVER)
#
#     server.receive_data(b"\x88\x84\x00\x00\x00\x00\x03\xe9\xff\xff")
#     self.assertIsInstance(server.parser_exc, UnicodeDecodeError)
#     self.assertEqual(
#         str(server.parser_exc),
#         "'utf-8' codec can't decode byte 0xff in position 0: invalid start byte",
#     )
#     self.assertConnectionFailing(
#         server, CloseCode.INVALID_DATA, "invalid start byte at position 0"
#     )
#     self.assertIs(server.state, CLOSING)
#
# def test_client_sends_close_twice(self):
#     client = Protocol(CLIENT)
#     with self.enforce_mask(b"\x00\x00\x00\x00"):
#         client.send_close(CloseCode.GOING_AWAY)
#     self.assertEqual(client.data_to_send(), [b"\x88\x82\x00\x00\x00\x00\x03\xe9"])
#     with self.assertRaises(InvalidState) as raised:
#         client.send_close(CloseCode.GOING_AWAY)
#     self.assertEqual(str(raised.exception), "connection is closing")
#
# def test_server_sends_close_twice(self):
#     server = Protocol(SERVER)
#     server.send_close(CloseCode.NORMAL_CLOSURE)
#     self.assertEqual(server.data_to_send(), [b"\x88\x02\x03\xe8"])
#     with self.assertRaises(InvalidState) as raised:
#         server.send_close(CloseCode.NORMAL_CLOSURE)
#     self.assertEqual(str(raised.exception), "connection is closing")
#
# def test_client_sends_close_after_connection_is_closed(self):
#     client = Protocol(CLIENT)
#     client.receive_eof()
#     with self.assertRaises(InvalidState) as raised:
#         client.send_close(CloseCode.GOING_AWAY)
#     self.assertEqual(str(raised.exception), "connection is closed")
#
# def test_server_sends_close_after_connection_is_closed(self):
#     server = Protocol(SERVER)
#     server.receive_eof()
#     with self.assertRaises(InvalidState) as raised:
#         server.send_close(CloseCode.NORMAL_CLOSURE)
#     self.assertEqual(str(raised.exception), "connection is closed")
#
