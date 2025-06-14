from testing import assert_equal, assert_raises, assert_true
from collections import Optional
from memory import UnsafePointer

from websockets.aliases import Bytes
from websockets.frames import (
    Close,
    Frame,
    CloseCode,
    OpCode,
)
from websockets.http import HTTPResponse
from websockets.protocol import Event, CLIENT, SERVER, OPEN
from websockets.protocol.base import (
    close_expected,
    fail,
    get_close_exc,
    receive_data,
    receive_eof,
    send_binary,
    send_close,
    send_continuation,
    send_frame,
    send_ping,
    send_text,
    Protocol,
)
from websockets.streams import StreamReader
from websockets.utils.bytes import str_to_bytes
from testutils import assert_bytes_equal

# 129 is 0x81, 4 is the length of the payload, 83 is 'S', 112 is 'p', 97 is 'a', 109 is 'm'
alias unmasked_text_frame_data = Bytes(129, 4, 83, 112, 97, 109)
# 129 is 0x81, 132 is 0x84, 0 is the first byte of the mask, 255 is the second byte of the mask
alias masked_text_frame_data = Bytes(129, 132, 0, 255, 0, 255, 83, 143, 97, 146)

# '😀' is 240, 159, 152, 128
alias smiley_data = Bytes(240, 159, 152, 128)

# 129 is 0x81, 132 is 0x84, 0 is the first byte of the mask, 0 is the second byte of the mask, 240, ... is '😀'
alias smiley_masked_text_frame_data = Bytes(129, 132, 0, 0, 0, 0) + smiley_data
# 129 is 0x81, 4 is the length of the payload, 240, ... is '😀'
alias smiley_unmasked_text_frame_data = Bytes(129, 4, 240, 159, 152, 128)


fn gen_mask() -> Bytes:
    return Bytes(0, 0, 0, 0)


struct DummyProtocol[side_param: Int](Protocol):
    """Protocol struct for testing purposes."""

    alias side = side_param
    var state: Int
    var reader: StreamReader
    var writes: Bytes
    var events: List[Event]
    var parser_exc: Optional[Error]
    var handshake_exc: Optional[Error]
    var curr_size: Optional[Int]
    # Close code and reason, set when a close frame is sent or received.
    var close_rcvd: Optional[Close]
    var close_sent: Optional[Close]
    var close_rcvd_then_sent: Optional[Bool]
    var eof_sent: Bool
    var discard_sent: Bool
    var expect_cont_frame: Bool

    fn __init__(
        out self,
        state: Int,
        owned reader: StreamReader,
        writes: Bytes,
        events: List[Event],
    ):
        self.state = state
        self.reader = reader^
        self.writes = writes
        self.events = events
        self.parser_exc = None
        self.handshake_exc = None
        self.curr_size = None
        self.close_rcvd = None
        self.close_sent = None
        self.close_rcvd_then_sent = None
        self.eof_sent = False
        self.discard_sent = False
        self.expect_cont_frame = False

    fn get_reader_ptr(self) -> UnsafePointer[StreamReader]:
        """Get the reader of the protocol."""
        return UnsafePointer(to=self.reader)

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

    fn process_response(mut self, response: HTTPResponse) raises -> None:
        """Process the handshare response from the server."""
        constrained[
            Self.side == CLIENT,
            "Protocol.process_response() is only available for client connections.",
        ]()

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

    fn get_handshake_exc(self) -> Optional[Error]:
        """Get the handshake exception."""
        return self.handshake_exc

    fn set_handshake_exc(mut self, exc: Optional[Error]) -> None:
        """Set the handshake exception."""
        self.handshake_exc = exc


# ===-------------------------------------------------------------------===#
# Test frame masking.
# ===-------------------------------------------------------------------===#


fn test_client_receives_unmasked_frame() raises:
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())

    s = Bytes(129, 4) + str_to_bytes("Spam")
    receive_data(client, s)

    events = client.events_received()
    assert_true(events[0].isa[Frame]())
    assert_bytes_equal(
        events[0][Frame].data, Frame(OpCode.OP_TEXT, str_to_bytes("Spam")).data
    )


fn test_client_sends_masked_frame() raises:
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())

    fn gen_mask() -> Bytes:
        return Bytes(0, 255, 0, 255)

    send_text[gen_mask_func=gen_mask](client, str_to_bytes("Spam"), True)
    assert_bytes_equal(client.data_to_send(), masked_text_frame_data)


fn test_server_sends_unmasked_frame() raises:
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    send_text(server, str_to_bytes("Spam"), True)
    assert_bytes_equal(server.data_to_send(), unmasked_text_frame_data)


fn test_server_receives_masked_frame() raises:
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data(server, masked_text_frame_data)
    events = server.events_received()
    assert_true(events[0].isa[Frame]())
    assert_bytes_equal(
        events[0][Frame].data, Frame(OpCode.OP_TEXT, str_to_bytes("Spam")).data
    )


fn test_client_receives_masked_frame() raises:
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data(client, masked_text_frame_data)
    events = client.events_received()
    assert_equal(
        events[0][Frame],
        Frame(
            OpCode.OP_CLOSE,
            Close(
                CloseCode.CLOSE_CODE_PROTOCOL_ERROR, "ProtocolError: incorrect masking"
            ).serialize(),
            fin=True,
        ),
    )


fn test_server_receives_unmasked_frame() raises:
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data[gen_mask_func=gen_mask](server, unmasked_text_frame_data)
    events = server.events_received()
    assert_equal(
        events[0][Frame],
        Frame(
            OpCode.OP_CLOSE,
            Close(
                CloseCode.CLOSE_CODE_PROTOCOL_ERROR, "ProtocolError: incorrect masking"
            ).serialize(),
            fin=True,
        ),
    )


# ===-------------------------------------------------------------------===#
# Test continuation frames without text or binary frames.
# ===-------------------------------------------------------------------===#


fn test_client_sends_unexpected_continuation() raises:
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    with assert_raises(contains="ProtocolError: unexpected continuation frame"):
        send_continuation(client, str_to_bytes(""), fin=False)


fn test_server_sends_unexpected_continuation() raises:
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    with assert_raises(contains="ProtocolError: unexpected continuation frame"):
        send_continuation(server, str_to_bytes(""), fin=False)


fn test_client_receives_unexpected_continuation() raises:
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data(client, Bytes(0, 0))
    events = client.events_received()
    assert_equal(
        String(client.parser_exc.value()),
        "ProtocolError: unexpected continuation frame",
    )
    assert_equal(
        events[0][Frame],
        Frame(
            OpCode.OP_CLOSE,
            Close(
                CloseCode.CLOSE_CODE_PROTOCOL_ERROR,
                "ProtocolError: unexpected continuation frame",
            ).serialize(),
            fin=True,
        ),
    )


fn test_server_receives_unexpected_continuation() raises:
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data[gen_mask_func=gen_mask](server, Bytes(0, 128, 0, 0, 0, 0))
    events = server.events_received()
    assert_equal(
        String(server.parser_exc.value()),
        "ProtocolError: unexpected continuation frame",
    )
    assert_equal(
        events[0][Frame],
        Frame(
            OpCode.OP_CLOSE,
            Close(
                CloseCode.CLOSE_CODE_PROTOCOL_ERROR,
                "ProtocolError: unexpected continuation frame",
            ).serialize(),
            fin=True,
        ),
    )


fn test_client_sends_continuation_after_sending_close() raises:
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    # Since it isn't possible to send a close frame in a fragmented
    # message (see test_client_send_close_in_fragmented_message), in fact,
    # this is the same test as test_client_sends_unexpected_continuation.
    send_close[gen_mask_func=gen_mask](client, CloseCode.CLOSE_CODE_GOING_AWAY)
    assert_bytes_equal(client.data_to_send(), Bytes(136, 130, 0, 0, 0, 0, 3, 233))
    with assert_raises(contains="ProtocolError: unexpected continuation frame"):
        send_continuation(client, str_to_bytes(""), fin=False)


fn test_server_sends_continuation_after_sending_close() raises:
    # Since it isn't possible to send a close frame in a fragmented
    # message (see test_server_send_close_in_fragmented_message), in fact,
    # this is the same test as test_server_sends_unexpected_continuation.
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    send_close(server, CloseCode.CLOSE_CODE_NORMAL_CLOSURE)
    assert_bytes_equal(server.data_to_send(), Bytes(136, 2, 3, 232))
    with assert_raises(contains="ProtocolError: unexpected continuation frame"):
        send_continuation(server, Bytes(), fin=False)


fn test_client_receives_continuation_after_receiving_close() raises:
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data[gen_mask_func=gen_mask](client, Bytes(136, 2, 3, 232))
    events = client.events_received()
    assert_equal(len(events), 1)
    close_frame = Frame(
        OpCode.OP_CLOSE,
        Close(CloseCode.CLOSE_CODE_NORMAL_CLOSURE, "").serialize(),
        fin=True,
    )
    assert_equal(events[0][Frame], close_frame)
    assert_bytes_equal(
        client.data_to_send(), close_frame.serialize[gen_mask_func=gen_mask](mask=True)
    )

    print("Receiving data for second time")
    receive_data(client, Bytes(0, 0))

    events = client.events_received()
    assert_equal(len(events), 0)
    assert_bytes_equal(client.data_to_send(), Bytes())


fn test_server_receives_continuation_after_receiving_close() raises:
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data[gen_mask_func=gen_mask](server, Bytes(136, 130, 0, 0, 0, 0, 3, 233))
    events = server.events_received()
    close_frame = Frame(
        OpCode.OP_CLOSE,
        Close(CloseCode.CLOSE_CODE_GOING_AWAY, "").serialize(),
        fin=True,
    )
    assert_equal(events[0][Frame], close_frame)
    assert_bytes_equal(
        server.data_to_send(), close_frame.serialize[gen_mask_func=gen_mask](mask=False)
    )
    receive_data(server, Bytes(0, 128, 0, 255, 0, 255))

    events = server.events_received()
    assert_equal(len(events), 0)
    assert_bytes_equal(server.data_to_send(), Bytes())


# ===-------------------------------------------------------------------===#
# Test text frames and continuation frames.
# ===-------------------------------------------------------------------===#


fn test_client_sends_text() raises:
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    send_text[gen_mask_func=gen_mask](client, str_to_bytes("Hello world"))
    data_to_send = client.data_to_send()

    expected = Bytes(
        129, 139, 0, 0, 0, 0, 72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100
    )
    assert_bytes_equal(data_to_send, expected)


fn test_server_sends_text() raises:
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    send_text(server, str_to_bytes("Hello world"))
    expected = Bytes(129, 11, 72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100)
    assert_bytes_equal(server.data_to_send(), expected)


fn test_client_receives_text() raises:
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data[gen_mask_func=gen_mask](client, smiley_unmasked_text_frame_data)
    expected_frame = Frame(OpCode.OP_TEXT, smiley_data)

    events = client.events_received()
    assert_equal(events[0][Frame], expected_frame)


fn test_server_receives_text() raises:
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data(server, smiley_masked_text_frame_data)
    expected_frame = Frame(OpCode.OP_TEXT, smiley_data)

    events = server.events_received()
    assert_equal(events[0][Frame], expected_frame)


# TODO: Implement the max_size in the protocol
# fn test_client_receives_text_over_size_limit() raises:
#     client = DummyProtocol[CLIENT, max_size=3](OPEN, StreamReader(), Bytes(), List[Event]())
#
#     # Send a 4-byte text frame containing '😀' (240, 159, 152, 128)
#     receive_data(client, Bytes(129, 4, 240, 159, 152, 128))
#
#     events = client.events_received()
#     assert_equal(String(client.parser_exc.value()), "PayloadTooBig: over size limit (4 > 3 bytes)")
#     assert_equal(events[0][Frame], Frame(OpCode.OP_CLOSE, Close(CloseCode.CLOSE_CODE_MESSAGE_TOO_BIG, "over size limit (4 > 3 bytes)").serialize(), fin=True))

# TODO: Implement the max_size in the protocol
# fn test_server_receives_text_over_size_limit() raises:
#     server = DummyProtocol[SERVER, max_size=3](OPEN, StreamReader(), Bytes(), List[Event]())
#
#     # Send a 4-byte text frame containing '😀' (240, 159, 152, 128)
#     receive_data(server, Bytes(129, 132, 0, 0, 0, 0, 240, 159, 152, 128))
#
#     events = server.events_received()
#     assert_equal(String(server.parser_exc.value()), "PayloadTooBig: over size limit (4 > 3 bytes)")
#     assert_equal(events[0][Frame], Frame(OpCode.OP_CLOSE, Close(CloseCode.CLOSE_CODE_MESSAGE_TOO_BIG, "over size limit (4 > 3 bytes)").serialize(), fin=True))


fn test_client_sends_fragmented_text() raises:
    """The test verifies that a client can properly fragment and send a text message containing emoji data across multiple frames with proper masking.
    """
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())

    # First fragment
    send_text[gen_mask_func=gen_mask](client, smiley_data[:2], fin=False)
    assert_bytes_equal(client.data_to_send(), Bytes(1, 130, 0, 0, 0, 0, 240, 159))

    # Second fragment
    send_continuation[gen_mask_func=gen_mask](
        client, smiley_data[2:] + smiley_data[:2], fin=False
    )
    assert_bytes_equal(
        client.data_to_send(), Bytes(0, 132, 0, 0, 0, 0, 152, 128, 240, 159)
    )

    # Final fragment
    send_continuation[gen_mask_func=gen_mask](client, smiley_data[2:], fin=True)
    assert_bytes_equal(client.data_to_send(), Bytes(128, 130, 0, 0, 0, 0, 152, 128))


fn test_server_sends_fragmented_text() raises:
    """The test verifies that a server can properly fragment and send a text message containing emoji data across multiple frames.
    """
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())

    # First fragment
    send_text(server, smiley_data[:2], fin=False)
    assert_bytes_equal(server.data_to_send(), Bytes(1, 2, 240, 159))

    # Second fragment
    send_continuation(server, smiley_data[2:] + smiley_data[:2], fin=False)
    assert_bytes_equal(server.data_to_send(), Bytes(0, 4, 152, 128, 240, 159))

    # Final fragment
    send_continuation(server, smiley_data[2:], fin=True)
    assert_bytes_equal(server.data_to_send(), Bytes(128, 2, 152, 128))


fn test_client_receives_fragmented_text() raises:
    """The test verifies that a client can properly receive fragmented text messages containing emoji data.
    """
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())

    # First fragment
    receive_data(client, Bytes(1, 2, 240, 159))
    events = client.events_received()
    assert_equal(events[0][Frame], Frame(OpCode.OP_TEXT, smiley_data[:2], fin=False))

    # Second fragment
    receive_data(client, Bytes(0, 4, 152, 128, 240, 159))
    events = client.events_received()
    assert_equal(
        events[0][Frame],
        Frame(OpCode.OP_CONT, smiley_data[2:] + smiley_data[:2], fin=False),
    )

    # Final fragment
    receive_data(client, Bytes(128, 2, 152, 128))
    events = client.events_received()
    assert_equal(events[0][Frame], Frame(OpCode.OP_CONT, smiley_data[2:]))


fn test_server_receives_fragmented_text() raises:
    """The test verifies that a server can properly receive fragmented text messages containing emoji data.
    """
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())

    # First fragment
    receive_data(server, Bytes(1, 130, 0, 0, 0, 0, 240, 159))
    events = server.events_received()
    assert_equal(events[0][Frame], Frame(OpCode.OP_TEXT, smiley_data[:2], fin=False))

    # Second fragment
    receive_data(server, Bytes(0, 132, 0, 0, 0, 0, 152, 128, 240, 159))
    events = server.events_received()
    assert_equal(
        events[0][Frame],
        Frame(OpCode.OP_CONT, smiley_data[2:] + smiley_data[:2], fin=False),
    )

    # Final fragment
    receive_data(server, Bytes(128, 130, 0, 0, 0, 0, 152, 128))
    events = server.events_received()
    assert_equal(events[0][Frame], Frame(OpCode.OP_CONT, smiley_data[2:]))


# TODO: Implement the max_size in the protocol
# fn test_client_receives_fragmented_text_over_size_limit() raises:
#     """The test verifies that a client properly handles fragmented text messages that exceed the size limit."""
#     client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
#
#     # First fragment
#     receive_data(client, Bytes(1, 2, 240, 159))
#     events = client.events_received()
#     assert_equal(events[0][Frame], Frame(OpCode.OP_TEXT, smiley_data[:2], fin=False))
#
#     # Second fragment exceeds size limit
#     receive_data(client, Bytes(128, 2, 152, 128))
#     events = client.events_received()
#     assert_equal(String(client.parser_exc.value()), "PayloadTooBig: over size limit (2 > 1 bytes)")
#     assert_equal(events[0][Frame], Frame(OpCode.OP_CLOSE, Close(CloseCode.CLOSE_CODE_MESSAGE_TOO_BIG, "over size limit (2 > 1 bytes)").serialize(), fin=True))

# TODO: Implement the max_size in the protocol
# fn test_server_receives_fragmented_text_over_size_limit() raises:
#     """The test verifies that a server properly handles fragmented text messages that exceed the size limit."""
#     server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
#
#     # First fragment
#     receive_data(server, Bytes(1, 130, 0, 0, 0, 0, 240, 159))
#     events = server.events_received()
#     assert_equal(events[0][Frame], Frame(OpCode.OP_TEXT, smiley_data[:2], fin=False))
#
#     # Second fragment exceeds size limit
#     receive_data(server, Bytes(128, 130, 0, 0, 0, 0, 152, 128))
#     events = server.events_received()
#     assert_equal(String(server.parser_exc.value()), "PayloadTooBig: over size limit (2 > 1 bytes)")
#     assert_equal(events[0][Frame], Frame(OpCode.OP_CLOSE, Close(CloseCode.CLOSE_CODE_MESSAGE_TOO_BIG, "over size limit (2 > 1 bytes)").serialize(), fin=True))


fn test_client_sends_unexpected_text() raises:
    """The test verifies that a client cannot send a text frame after sending a text frame without the FIN bit set.
    """
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    send_text[gen_mask_func=gen_mask](client, Bytes(), fin=False)
    with assert_raises(contains="ProtocolError: expected a continuation frame"):
        send_text[gen_mask_func=gen_mask](client, Bytes(), fin=False)


fn test_server_sends_unexpected_text() raises:
    """The test verifies that a server cannot send a text frame after sending a text frame without the FIN bit set.
    """
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    send_text(server, Bytes(), fin=False)
    with assert_raises(contains="ProtocolError: expected a continuation frame"):
        send_text(server, Bytes(), fin=False)


fn test_client_receives_unexpected_text() raises:
    """The test verifies that a client properly handles receiving an unexpected text frame.
    """
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())

    # First text frame without FIN bit
    receive_data(client, Bytes(1, 0))
    events = client.events_received()
    assert_equal(events[0][Frame], Frame(OpCode.OP_TEXT, Bytes(), fin=False))

    # Second unexpected text frame
    receive_data(client, Bytes(1, 0))
    events = client.events_received()
    assert_equal(
        String(client.parser_exc.value()),
        "ProtocolError: expected a continuation frame",
    )
    assert_equal(
        events[0][Frame],
        Frame(
            OpCode.OP_CLOSE,
            Close(
                CloseCode.CLOSE_CODE_PROTOCOL_ERROR,
                "ProtocolError: expected a continuation frame",
            ).serialize(),
            fin=True,
        ),
    )


fn test_server_receives_unexpected_text() raises:
    """The test verifies that a server properly handles receiving an unexpected text frame.
    """
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())

    # First text frame without FIN bit
    receive_data[gen_mask_func=gen_mask](server, Bytes(1, 128, 0, 0, 0, 0))
    events = server.events_received()
    assert_equal(events[0][Frame], Frame(OpCode.OP_TEXT, Bytes(), fin=False))

    # Second unexpected text frame
    receive_data[gen_mask_func=gen_mask](server, Bytes(1, 128, 0, 0, 0, 0))
    events = server.events_received()
    assert_equal(
        String(server.parser_exc.value()),
        "ProtocolError: expected a continuation frame",
    )
    assert_equal(
        events[0][Frame],
        Frame(
            OpCode.OP_CLOSE,
            Close(
                CloseCode.CLOSE_CODE_PROTOCOL_ERROR,
                "ProtocolError: expected a continuation frame",
            ).serialize(),
            fin=True,
        ),
    )


fn test_client_sends_text_after_sending_close() raises:
    """The test verifies that a client cannot send text frames after sending a close frame.
    """
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    send_close[gen_mask_func=gen_mask](client, CloseCode.CLOSE_CODE_GOING_AWAY)
    assert_bytes_equal(client.data_to_send(), Bytes(136, 130, 0, 0, 0, 0, 3, 233))
    with assert_raises(contains="InvalidState: connection is 2"):
        send_text[gen_mask_func=gen_mask](client, Bytes())


fn test_server_sends_text_after_sending_close() raises:
    """The test verifies that a server cannot send text frames after sending a close frame.
    """
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    send_close(server, CloseCode.CLOSE_CODE_NORMAL_CLOSURE)
    assert_bytes_equal(server.data_to_send(), Bytes(136, 2, 3, 232))
    with assert_raises(contains="InvalidState: connection is 2"):
        send_text(server, Bytes())


fn test_client_receives_text_after_receiving_close() raises:
    """The test verifies that a client properly ignores text frames after receiving a close frame.
    """
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())

    # Receive close frame
    receive_data[gen_mask_func=gen_mask](client, Bytes(136, 2, 3, 232))
    events = client.events_received()
    close_frame = Frame(
        OpCode.OP_CLOSE,
        Close(CloseCode.CLOSE_CODE_NORMAL_CLOSURE, "").serialize(),
        fin=True,
    )
    assert_equal(events[0][Frame], close_frame)
    assert_bytes_equal(
        client.data_to_send(), close_frame.serialize[gen_mask_func=gen_mask](mask=True)
    )

    # Receive text frame after close
    receive_data(client, Bytes(129, 0))
    events = client.events_received()
    assert_equal(len(events), 0)
    assert_bytes_equal(client.data_to_send(), Bytes())


fn test_server_receives_text_after_receiving_close() raises:
    """The test verifies that a server properly ignores text frames after receiving a close frame.
    """
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())

    # Receive close frame
    receive_data[gen_mask_func=gen_mask](server, Bytes(136, 130, 0, 0, 0, 0, 3, 233))
    events = server.events_received()
    close_frame = Frame(
        OpCode.OP_CLOSE,
        Close(CloseCode.CLOSE_CODE_GOING_AWAY, "").serialize(),
        fin=True,
    )
    assert_equal(events[0][Frame], close_frame)
    assert_bytes_equal(
        server.data_to_send(), close_frame.serialize[gen_mask_func=gen_mask](mask=False)
    )

    # Receive text frame after close
    receive_data(server, Bytes(129, 128, 0, 255, 0, 255))
    events = server.events_received()
    assert_equal(len(events), 0)
    assert_bytes_equal(server.data_to_send(), Bytes())


# ===-------------------------------------------------------------------===#
# Test binary frames and continuation frames.
# ===-------------------------------------------------------------------===#


fn test_client_sends_binary() raises:
    """The test verifies that a client can properly send binary data with masking."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    send_binary[gen_mask_func=gen_mask](client, Bytes(1, 2, 254, 255))
    assert_bytes_equal(
        client.data_to_send(), Bytes(130, 132, 0, 0, 0, 0, 1, 2, 254, 255)
    )


fn test_server_sends_binary() raises:
    """The test verifies that a server can properly send binary data without masking."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    send_binary(server, Bytes(1, 2, 254, 255))
    assert_bytes_equal(server.data_to_send(), Bytes(130, 4, 1, 2, 254, 255))


fn test_client_receives_binary() raises:
    """The test verifies that a client can properly receive binary data."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data(client, Bytes(130, 4, 1, 2, 254, 255))
    events = client.events_received()
    assert_equal(events[0][Frame], Frame(OpCode.OP_BINARY, Bytes(1, 2, 254, 255)))


fn test_server_receives_binary() raises:
    """The test verifies that a server can properly receive binary data."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data(server, Bytes(130, 132, 0, 0, 0, 0, 1, 2, 254, 255))
    events = server.events_received()
    assert_equal(events[0][Frame], Frame(OpCode.OP_BINARY, Bytes(1, 2, 254, 255)))


# TODO: Implement the max_size in the protocol
# fn test_client_receives_binary_over_size_limit() raises:
#     """The test verifies that a client properly handles binary data exceeding size limits."""
#     client = DummyProtocol[CLIENT, max_size=3](OPEN, StreamReader(), Bytes(), List[Event]())
#     receive_data(client, Bytes(130, 4, 1, 2, 254, 255))
#     assert_equal(String(client.parser_exc.value()), "PayloadTooBig: over size limit (4 > 3 bytes)")
#     assert_equal(events[0][Frame], Frame(OpCode.OP_CLOSE, Close(CloseCode.CLOSE_CODE_MESSAGE_TOO_BIG, "over size limit (4 > 3 bytes)").serialize(), fin=True))

# TODO: Implement the max_size in the protocol
# fn test_server_receives_binary_over_size_limit() raises:
#     """The test verifies that a server properly handles binary data exceeding size limits."""
#     server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
#     receive_data(server, Bytes(130, 132, 0, 0, 0, 0, 1, 2, 254, 255))
#     events = server.events_received()
#     assert_equal(String(server.parser_exc.value()), "PayloadTooBig: over size limit (4 > 3 bytes)")
#     assert_equal(events[0][Frame], Frame(OpCode.OP_CLOSE, Close(CloseCode.CLOSE_CODE_MESSAGE_TOO_BIG, "over size limit (4 > 3 bytes)").serialize(), fin=True))


fn test_client_sends_fragmented_binary() raises:
    """The test verifies that a client can properly fragment and send binary data with masking.
    """
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())

    # First fragment
    send_binary[gen_mask_func=gen_mask](client, Bytes(1, 2), fin=False)
    assert_bytes_equal(client.data_to_send(), Bytes(2, 130, 0, 0, 0, 0, 1, 2))

    # Second fragment
    send_continuation[gen_mask_func=gen_mask](client, Bytes(238, 255, 1, 2), fin=False)
    assert_bytes_equal(client.data_to_send(), Bytes(0, 132, 0, 0, 0, 0, 238, 255, 1, 2))

    # Final fragment
    send_continuation[gen_mask_func=gen_mask](client, Bytes(238, 255), fin=True)
    assert_bytes_equal(client.data_to_send(), Bytes(128, 130, 0, 0, 0, 0, 238, 255))


fn test_server_sends_fragmented_binary() raises:
    """The test verifies that a server can properly fragment and send binary data without masking.
    """
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())

    # First fragment
    send_binary(server, Bytes(1, 2), fin=False)
    assert_bytes_equal(server.data_to_send(), Bytes(2, 2, 1, 2))

    # Second fragment
    send_continuation(server, Bytes(238, 255, 1, 2), fin=False)
    assert_bytes_equal(server.data_to_send(), Bytes(0, 4, 238, 255, 1, 2))

    # Final fragment
    send_continuation(server, Bytes(238, 255), fin=True)
    assert_bytes_equal(server.data_to_send(), Bytes(128, 2, 238, 255))


fn test_client_receives_fragmented_binary() raises:
    """The test verifies that a client can properly receive fragmented binary data."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())

    # First fragment
    receive_data(client, Bytes(2, 2, 1, 2))
    events = client.events_received()
    assert_equal(events[0][Frame], Frame(OpCode.OP_BINARY, Bytes(1, 2), fin=False))

    # Second fragment
    receive_data(client, Bytes(0, 4, 254, 255, 1, 2))
    events = client.events_received()
    assert_equal(
        events[0][Frame], Frame(OpCode.OP_CONT, Bytes(254, 255, 1, 2), fin=False)
    )

    # Final fragment
    receive_data(client, Bytes(128, 2, 254, 255))
    events = client.events_received()
    assert_equal(events[0][Frame], Frame(OpCode.OP_CONT, Bytes(254, 255)))


fn test_server_receives_fragmented_binary() raises:
    """The test verifies that a server can properly receive fragmented binary data."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())

    # First fragment
    receive_data(server, Bytes(2, 130, 0, 0, 0, 0, 1, 2))
    events = server.events_received()
    assert_equal(events[0][Frame], Frame(OpCode.OP_BINARY, Bytes(1, 2), fin=False))

    # Second fragment
    receive_data(server, Bytes(0, 132, 0, 0, 0, 0, 238, 255, 1, 2))
    events = server.events_received()
    assert_equal(
        events[0][Frame], Frame(OpCode.OP_CONT, Bytes(238, 255, 1, 2), fin=False)
    )

    # Final fragment
    receive_data(server, Bytes(128, 130, 0, 0, 0, 0, 254, 255))
    events = server.events_received()
    assert_equal(events[0][Frame], Frame(OpCode.OP_CONT, Bytes(254, 255)))


# TODO: Implement the max_size in the protocol
# fn test_client_receives_fragmented_binary_over_size_limit() raises:
#     """The test verifies that a client properly handles fragmented binary data exceeding size limits."""
#     client = DummyProtocol[CLIENT, max_size=3](OPEN, StreamReader(), Bytes(), List[Event]())
#
#     # First fragment
#     receive_data(client, Bytes(2, 2, 1, 2))
#     events = client.events_received()
#     assert_equal(events[0][Frame], Frame(OpCode.OP_BINARY, Bytes(1, 2), fin=False))
#
#     # Second fragment exceeds size limit
#     receive_data(client, Bytes(128, 2, 254, 255))
#     events = client.events_received()
#     assert_equal(String(client.parser_exc.value()), "PayloadTooBig: over size limit (2 > 1 bytes)")
#     assert_equal(events[0][Frame], Frame(OpCode.OP_CLOSE, Close(CloseCode.CLOSE_CODE_MESSAGE_TOO_BIG, "over size limit (2 > 1 bytes)").serialize(), fin=True))

# TODO: Implement the max_size in the protocol
# fn test_server_receives_fragmented_binary_over_size_limit() raises:
#     """The test verifies that a server properly handles fragmented binary data exceeding size limits."""
#     server = DummyProtocol[SERVER, max_size=3](OPEN, StreamReader(), Bytes(), List[Event]())
#
#     # First fragment
#     receive_data(server, Bytes(2, 130, 0, 0, 0, 0, 1, 2))
#     events = server.events_received()
#     assert_equal(events[0][Frame], Frame(OpCode.OP_BINARY, Bytes(1, 2), fin=False))
#
#     # Second fragment exceeds size limit
#     receive_data(server, Bytes(128, 130, 0, 0, 0, 0, 254, 255))
#     events = server.events_received()
#     assert_equal(String(server.parser_exc.value()), "PayloadTooBig: over size limit (2 > 1 bytes)")
#     assert_equal(events[0][Frame], Frame(OpCode.OP_CLOSE, Close(CloseCode.CLOSE_CODE_MESSAGE_TOO_BIG, "over size limit (2 > 1 bytes)").serialize(), fin=True))
#


fn test_client_sends_unexpected_binary() raises:
    """The test verifies that a client cannot send a binary frame after sending a binary frame without the FIN bit set.
    """
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    send_binary[gen_mask_func=gen_mask](client, Bytes(), fin=False)
    with assert_raises(contains="ProtocolError: expected a continuation frame"):
        send_binary[gen_mask_func=gen_mask](client, Bytes(), fin=False)


fn test_server_sends_unexpected_binary() raises:
    """The test verifies that a server cannot send a binary frame after sending a binary frame without the FIN bit set.
    """
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    send_binary(server, Bytes(), fin=False)
    with assert_raises(contains="ProtocolError: expected a continuation frame"):
        send_binary(server, Bytes(), fin=False)


fn test_client_receives_unexpected_binary() raises:
    """The test verifies that a client properly handles receiving an unexpected binary frame.
    """
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())

    # First binary frame without FIN bit
    receive_data(client, Bytes(2, 0))
    events = client.events_received()
    assert_equal(events[0][Frame], Frame(OpCode.OP_BINARY, Bytes(), fin=False))

    # Second unexpected binary frame
    receive_data(client, Bytes(2, 0))
    events = client.events_received()
    assert_equal(
        String(client.parser_exc.value()),
        "ProtocolError: expected a continuation frame",
    )
    assert_equal(
        events[0][Frame],
        Frame(
            OpCode.OP_CLOSE,
            Close(
                CloseCode.CLOSE_CODE_PROTOCOL_ERROR,
                "ProtocolError: expected a continuation frame",
            ).serialize(),
            fin=True,
        ),
    )


fn test_server_receives_unexpected_binary() raises:
    """The test verifies that a server properly handles receiving an unexpected binary frame.
    """
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())

    # First binary frame without FIN bit
    receive_data[gen_mask_func=gen_mask](server, Bytes(2, 128, 0, 0, 0, 0))
    events = server.events_received()
    assert_equal(events[0][Frame], Frame(OpCode.OP_BINARY, Bytes(), fin=False))

    # Second unexpected binary frame
    receive_data[gen_mask_func=gen_mask](server, Bytes(2, 128, 0, 0, 0, 0))
    events = server.events_received()
    assert_equal(
        String(server.get_parser_exc().value()),
        "ProtocolError: expected a continuation frame",
    )
    assert_equal(
        events[0][Frame],
        Frame(
            OpCode.OP_CLOSE,
            Close(
                CloseCode.CLOSE_CODE_PROTOCOL_ERROR,
                "ProtocolError: expected a continuation frame",
            ).serialize(),
            fin=True,
        ),
    )


fn test_client_sends_binary_after_sending_close() raises:
    """The test verifies that a client cannot send binary frames after sending a close frame.
    """
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    send_close[gen_mask_func=gen_mask](client, CloseCode.CLOSE_CODE_GOING_AWAY)
    assert_bytes_equal(client.data_to_send(), Bytes(136, 130, 0, 0, 0, 0, 3, 233))
    with assert_raises(contains="InvalidState: connection is 2"):
        send_binary[gen_mask_func=gen_mask](client, Bytes())


fn test_server_sends_binary_after_sending_close() raises:
    """The test verifies that a server cannot send binary frames after sending a close frame.
    """
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    send_close(server, CloseCode.CLOSE_CODE_NORMAL_CLOSURE)
    assert_bytes_equal(server.data_to_send(), Bytes(136, 2, 3, 232))
    with assert_raises(contains="InvalidState: connection is 2"):
        send_binary(server, Bytes())


fn test_client_receives_binary_after_receiving_close() raises:
    """The test verifies that a client properly ignores binary frames after receiving a close frame.
    """
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())

    # Receive close frame
    receive_data[gen_mask_func=gen_mask](client, Bytes(136, 2, 3, 232))
    events = client.events_received()
    close_frame = Frame(
        OpCode.OP_CLOSE,
        Close(CloseCode.CLOSE_CODE_NORMAL_CLOSURE, "").serialize(),
        fin=True,
    )
    assert_equal(events[0][Frame], close_frame)
    assert_bytes_equal(
        client.data_to_send(), close_frame.serialize[gen_mask_func=gen_mask](mask=True)
    )

    # Receive binary frame after close
    receive_data(client, Bytes(130, 0))
    events = client.events_received()
    assert_equal(len(events), 0)
    assert_bytes_equal(client.data_to_send(), Bytes())


fn test_server_receives_binary_after_receiving_close() raises:
    """The test verifies that a server properly ignores binary frames after receiving a close frame.
    """
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())

    # Receive close frame
    receive_data[gen_mask_func=gen_mask](server, Bytes(136, 130, 0, 0, 0, 0, 3, 233))
    events = server.events_received()
    close_frame = Frame(
        OpCode.OP_CLOSE,
        Close(CloseCode.CLOSE_CODE_GOING_AWAY, "").serialize(),
        fin=True,
    )
    assert_equal(events[0][Frame], close_frame)
    assert_bytes_equal(
        server.data_to_send(), close_frame.serialize[gen_mask_func=gen_mask](mask=False)
    )

    # Receive binary frame after close
    receive_data(server, Bytes(130, 128, 0, 255, 0, 255))
    events = server.events_received()
    assert_equal(len(events), 0)
    assert_bytes_equal(server.data_to_send(), Bytes())


# ===-------------------------------------------------------------------===#
# Test close frames.
# ===-------------------------------------------------------------------===#


fn test_close_code() raises:
    """Test that close code is properly received and parsed."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data(client, Bytes(136, 4, 3, 232, 79, 75))  # \x88\x04\x03\xe8OK
    events = client.events_received()
    assert_equal(
        events[0][Frame],
        Frame(
            OpCode.OP_CLOSE,
            Close(CloseCode.CLOSE_CODE_NORMAL_CLOSURE, "OK").serialize(),
            fin=True,
        ),
    )


fn test_close_reason() raises:
    """Test that close reason is properly received and parsed."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data[gen_mask_func=gen_mask](
        server, Bytes(136, 132, 0, 0, 0, 0, 3, 232, 79, 75)
    )  # \x88\x84\x00\x00\x00\x00\x03\xe8OK
    events = server.events_received()
    assert_equal(
        events[0][Frame],
        Frame(
            OpCode.OP_CLOSE,
            Close(CloseCode.CLOSE_CODE_NORMAL_CLOSURE, "OK").serialize(),
            fin=True,
        ),
    )


fn test_close_code_not_provided() raises:
    """Test handling when no close code is provided."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data[gen_mask_func=gen_mask](
        server, Bytes(136, 128, 0, 0, 0, 0)
    )  # \x88\x80\x00\x00\x00\x00
    events = server.events_received()
    assert_equal(events[0][Frame], Frame(OpCode.OP_CLOSE, Bytes(), fin=True))


fn test_close_reason_not_provided() raises:
    """Test handling when no close reason is provided."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data(client, Bytes(136, 0))  # \x88\x00
    events = client.events_received()
    assert_equal(events[0][Frame], Frame(OpCode.OP_CLOSE, Bytes(), fin=True))


fn test_close_code_not_available() raises:
    """Test that close code is ABNORMAL_CLOSURE when connection is closed without a code.
    """
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    client.set_eof_sent(True)
    assert_equal(Bool(client.get_close_rcvd()), False)


fn test_close_reason_not_available() raises:
    """Test that close reason is empty when connection is closed without a reason."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    server.set_eof_sent(True)
    assert_equal(Bool(server.get_close_rcvd()), False)


fn test_close_code_not_available_yet() raises:
    """Test that close code is None before connection is closed."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    assert_equal(Bool(server.get_close_rcvd()), False)


fn test_close_reason_not_available_yet() raises:
    """Test that close reason is None before connection is closed."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    assert_equal(Bool(client.get_close_rcvd()), False)


fn test_client_sends_close() raises:
    """Test that client properly sends a close frame."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    send_close[gen_mask_func=gen_mask](client)
    assert_bytes_equal(
        client.data_to_send(), Bytes(136, 128, 0, 0, 0, 0)
    )  # \x88\x80\x00\x00\x00\x00
    assert_equal(client.get_state(), 2)  # CLOSING


fn test_server_sends_close() raises:
    """Test that server properly sends a close frame."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    send_close(server)
    assert_bytes_equal(server.data_to_send(), Bytes(136, 0))  # \x88\x00
    assert_equal(server.get_state(), 2)  # CLOSING


fn test_client_receives_close() raises:
    """Test that client properly receives a close frame."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data[gen_mask_func=gen_mask](client, Bytes(136, 0))  # \x88\x00
    events = client.events_received()
    assert_equal(events[0][Frame], Frame(OpCode.OP_CLOSE, Bytes(), fin=True))
    assert_bytes_equal(
        client.data_to_send(),
        Frame(OpCode.OP_CLOSE, Bytes(), fin=True).serialize[gen_mask_func=gen_mask](
            mask=True
        ),
    )
    assert_equal(client.get_state(), 2)  # CLOSING


fn test_server_receives_close() raises:
    """Test that server properly receives a close frame."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data[gen_mask_func=gen_mask](
        server, Bytes(136, 128, 0, 0, 0, 0)
    )  # \x88\x80\x00\x00\x00\x00
    events = server.events_received()
    assert_equal(events[0][Frame], Frame(OpCode.OP_CLOSE, Bytes(), fin=True))
    assert_bytes_equal(
        server.data_to_send(),
        Frame(OpCode.OP_CLOSE, Bytes(), fin=True).serialize[gen_mask_func=gen_mask](
            mask=False
        ),
    )
    assert_equal(server.get_state(), 2)  # CLOSING


fn test_client_sends_close_then_receives_close() raises:
    """Test client-initiated close handshake on the client side."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())

    send_close[gen_mask_func=gen_mask](client)
    events = client.events_received()
    assert_equal(len(events), 0)
    expected = Frame(OpCode.OP_CLOSE, Bytes(), fin=True).serialize[
        gen_mask_func=gen_mask
    ](mask=True)
    data_to_send = client.data_to_send()
    assert_bytes_equal(data_to_send, expected)

    # Receive close
    receive_data[gen_mask_func=gen_mask](client, Bytes(136, 0))  # \x88\x00
    events = client.events_received()
    assert_equal(events[0][Frame], Frame(OpCode.OP_CLOSE, Bytes(), fin=True))
    assert_bytes_equal(client.data_to_send(), Bytes())

    # Receive EOF
    client.set_eof_sent(True)
    events = client.events_received()
    assert_equal(len(events), 0)
    assert_bytes_equal(client.data_to_send(), Bytes())


fn test_server_sends_close_then_receives_close() raises:
    """Test server-initiated close handshake on the server side."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())

    # Send close
    send_close[gen_mask_func=gen_mask](server)
    events = server.events_received()
    assert_equal(len(events), 0)
    assert_bytes_equal(
        server.data_to_send(),
        Frame(OpCode.OP_CLOSE, Bytes(), fin=True).serialize[gen_mask_func=gen_mask](
            mask=False
        ),
    )

    # Receive close
    receive_data[gen_mask_func=gen_mask](
        server, Bytes(136, 128, 0, 0, 0, 0)
    )  # \x88\x80\x00\x00\x00\x00
    events = server.events_received()
    assert_equal(events[0][Frame], Frame(OpCode.OP_CLOSE, Bytes(), fin=True))
    assert_bytes_equal(server.data_to_send(), Bytes())
    assert_equal(server.get_eof_sent(), True)

    # Receive EOF
    server.set_eof_sent(True)
    events = server.events_received()
    assert_equal(len(events), 0)
    assert_bytes_equal(server.data_to_send(), Bytes())


fn test_client_receives_close_then_sends_close() raises:
    """Test server-initiated close handshake on the client side."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())

    # Receive close
    receive_data[gen_mask_func=gen_mask](client, Bytes(136, 0))  # \x88\x00
    events = client.events_received()
    assert_equal(events[0][Frame], Frame(OpCode.OP_CLOSE, Bytes(), fin=True))
    assert_bytes_equal(
        client.data_to_send(),
        Frame(OpCode.OP_CLOSE, Bytes(), fin=True).serialize[gen_mask_func=gen_mask](
            mask=True
        ),
    )

    # Receive EOF
    client.set_eof_sent(True)
    events = client.events_received()
    assert_equal(len(events), 0)
    assert_bytes_equal(client.data_to_send(), Bytes())


fn test_server_receives_close_then_sends_close() raises:
    """Test client-initiated close handshake on the server side."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())

    # Receive close
    receive_data[gen_mask_func=gen_mask](
        server, Bytes(136, 128, 0, 0, 0, 0)
    )  # \x88\x80\x00\x00\x00\x00
    events = server.events_received()
    assert_equal(events[0][Frame], Frame(OpCode.OP_CLOSE, Bytes(), fin=True))
    assert_bytes_equal(
        server.data_to_send(),
        Frame(OpCode.OP_CLOSE, Bytes(), fin=True).serialize[gen_mask_func=gen_mask](
            mask=False
        ),
    )
    assert_equal(server.get_state(), 2)  # CLOSING

    # Receive EOF
    server.set_eof_sent(True)
    events = server.events_received()
    assert_equal(len(events), 0)
    assert_bytes_equal(server.data_to_send(), Bytes())


fn test_client_sends_close_with_code() raises:
    """Test that client properly sends a close frame with code."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    send_close[gen_mask_func=gen_mask](client, CloseCode.CLOSE_CODE_GOING_AWAY)
    assert_bytes_equal(client.data_to_send(), Bytes(136, 130, 0, 0, 0, 0, 3, 233))
    assert_equal(client.get_state(), 2)  # CLOSING


fn test_server_sends_close_with_code() raises:
    """Test that server properly sends a close frame with code."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    send_close(server, CloseCode.CLOSE_CODE_NORMAL_CLOSURE)
    assert_bytes_equal(server.data_to_send(), Bytes(136, 2, 3, 232))
    assert_equal(server.get_state(), 2)  # CLOSING


fn test_client_receives_close_with_code() raises:
    """Test that client properly receives a close frame with code."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data[gen_mask_func=gen_mask](
        client, Bytes(136, 2, 3, 232)
    )  # \x88\x02\x03\xe8
    events = client.events_received()
    close_frame = Frame(
        OpCode.OP_CLOSE,
        Close(CloseCode.CLOSE_CODE_NORMAL_CLOSURE, "").serialize(),
        fin=True,
    )
    assert_equal(events[0][Frame], close_frame)
    assert_bytes_equal(
        client.data_to_send(), close_frame.serialize[gen_mask_func=gen_mask](mask=True)
    )
    assert_equal(client.get_state(), 2)  # CLOSING


fn test_server_receives_close_with_code() raises:
    """Test that server properly receives a close frame with code."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data[gen_mask_func=gen_mask](server, Bytes(136, 130, 0, 0, 0, 0, 3, 233))
    events = server.events_received()
    close_frame = Frame(
        OpCode.OP_CLOSE,
        Close(CloseCode.CLOSE_CODE_GOING_AWAY, "").serialize(),
        fin=True,
    )
    assert_equal(events[0][Frame], close_frame)
    assert_bytes_equal(
        server.data_to_send(), close_frame.serialize[gen_mask_func=gen_mask](mask=False)
    )
    assert_equal(server.get_state(), 2)  # CLOSING


fn test_client_sends_close_with_code_and_reason() raises:
    """Test that client properly sends a close frame with code and reason."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    send_close[gen_mask_func=gen_mask](
        client, CloseCode.CLOSE_CODE_GOING_AWAY, "going away"
    )
    assert_bytes_equal(
        client.data_to_send(),
        Bytes(136, 140, 0, 0, 0, 0, 3, 233) + str_to_bytes("going away"),
    )
    assert_equal(client.get_state(), 2)  # CLOSING


fn test_server_sends_close_with_code_and_reason() raises:
    """Test that server properly sends a close frame with code and reason."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    send_close(server, CloseCode.CLOSE_CODE_NORMAL_CLOSURE, "OK")
    assert_bytes_equal(
        server.data_to_send(), Bytes(136, 4, 3, 232) + str_to_bytes("OK")
    )
    assert_equal(server.get_state(), 2)  # CLOSING


fn test_client_receives_close_with_code_and_reason() raises:
    """Test that client properly receives a close frame with code and reason."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data[gen_mask_func=gen_mask](
        client, Bytes(136, 4, 3, 232) + str_to_bytes("OK")
    )
    events = client.events_received()
    close_frame = Frame(
        OpCode.OP_CLOSE,
        Close(CloseCode.CLOSE_CODE_NORMAL_CLOSURE, "OK").serialize(),
        fin=True,
    )
    assert_equal(events[0][Frame], close_frame)
    assert_bytes_equal(
        client.data_to_send(), close_frame.serialize[gen_mask_func=gen_mask](mask=True)
    )
    assert_equal(client.get_state(), 2)  # CLOSING


fn test_server_receives_close_with_code_and_reason() raises:
    """Test that server properly receives a close frame with code and reason."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data[gen_mask_func=gen_mask](
        server, Bytes(136, 140, 0, 0, 0, 0, 3, 233) + str_to_bytes("going away")
    )
    events = server.events_received()
    close_frame = Frame(
        OpCode.OP_CLOSE,
        Close(CloseCode.CLOSE_CODE_GOING_AWAY, "going away").serialize(),
        fin=True,
    )
    assert_equal(events[0][Frame], close_frame)
    assert_bytes_equal(
        server.data_to_send(), close_frame.serialize[gen_mask_func=gen_mask](mask=False)
    )
    assert_equal(server.get_state(), 2)  # CLOSING


fn test_client_sends_close_with_reason_only() raises:
    """Test that client cannot send a close frame with reason only."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    with assert_raises(contains="ProtocolError: cannot send a reason without a code"):
        send_close[gen_mask_func=gen_mask](client, reason="going away")


fn test_server_sends_close_with_reason_only() raises:
    """Test that server cannot send a close frame with reason only."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    with assert_raises(contains="ProtocolError: cannot send a reason without a code"):
        send_close(server, reason="OK")


fn test_client_receives_close_with_truncated_code() raises:
    """Test that client properly handles receiving a close frame with truncated code."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data(client, Bytes(136, 1, 3))  # \x88\x01\x03
    events = client.events_received()
    assert_equal(
        String(client.parser_exc.value()), "ProtocolError: close frame too short"
    )
    assert_equal(
        events[0][Frame],
        Frame(
            OpCode.OP_CLOSE,
            Close(
                CloseCode.CLOSE_CODE_PROTOCOL_ERROR,
                "ProtocolError: close frame too short",
            ).serialize(),
            fin=True,
        ),
    )
    assert_equal(client.get_state(), 2)  # CLOSING


fn test_server_receives_close_with_truncated_code() raises:
    """Test that server properly handles receiving a close frame with truncated code."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data[gen_mask_func=gen_mask](
        server, Bytes(136, 129, 0, 0, 0, 0, 3)
    )  # \x88\x81\x00\x00\x00\x00\x03
    events = server.events_received()
    assert_equal(
        String(server.parser_exc.value()), "ProtocolError: close frame too short"
    )
    assert_equal(
        events[0][Frame],
        Frame(
            OpCode.OP_CLOSE,
            Close(
                CloseCode.CLOSE_CODE_PROTOCOL_ERROR,
                "ProtocolError: close frame too short",
            ).serialize(),
            fin=True,
        ),
    )
    assert_equal(server.get_state(), 2)  # CLOSING


# TODO: Implement when unicode is supported
# fn test_client_receives_close_with_non_utf8_reason() raises:
#     """Test that client properly handles receiving a close frame with non-UTF-8 reason."""
#     client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
#
#     # Send close frame with invalid UTF-8 bytes
#     receive_data(client, Bytes(136, 4, 3, 232, 255, 255))  # \x88\x04\x03\xe8\xff\xff
#     events = client.events_received()
#     assert_equal(String(client.parser_exc.value()), "UnicodeDecodeError: invalid start byte at position 0")
#     assert_equal(events[0][Frame], Frame(OpCode.OP_CLOSE, Close(CloseCode.CLOSE_CODE_INVALID_DATA, "invalid start byte at position 0").serialize(), fin=True))
#     assert_equal(client.get_state(), 2)  # CLOSING


# TODO: Implement when unicode is supported
# fn test_server_receives_close_with_non_utf8_reason() raises:
#     """Test that server properly handles receiving a close frame with non-UTF-8 reason."""
#     server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
#
#     # Send close frame with invalid UTF-8 bytes
#     receive_data[gen_mask_func=gen_mask](server, Bytes(136, 132, 0, 0, 0, 0, 3, 233, 255, 255))  # \x88\x84\x00\x00\x00\x00\x03\xe9\xff\xff
#     events = server.events_received()
#     assert_equal(String(server.parser_exc.value()), "UnicodeDecodeError: invalid start byte at position 0")
#     assert_equal(events[0][Frame], Frame(OpCode.OP_CLOSE, Close(CloseCode.CLOSE_CODE_INVALID_DATA, "invalid start byte at position 0").serialize(), fin=True))
#     assert_equal(server.get_state(), 2)  # CLOSING


fn test_client_sends_close_twice() raises:
    """Test that client cannot send close frame twice."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    send_close[gen_mask_func=gen_mask](client, CloseCode.CLOSE_CODE_GOING_AWAY)
    assert_bytes_equal(client.data_to_send(), Bytes(136, 130, 0, 0, 0, 0, 3, 233))
    with assert_raises(contains="InvalidState: connection is not open but 2"):
        send_close[gen_mask_func=gen_mask](client, CloseCode.CLOSE_CODE_GOING_AWAY)


fn test_server_sends_close_twice() raises:
    """Test that server cannot send close frame twice."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    send_close(server, CloseCode.CLOSE_CODE_NORMAL_CLOSURE)
    assert_bytes_equal(server.data_to_send(), Bytes(136, 2, 3, 232))
    with assert_raises(contains="InvalidState: connection is not open but 2"):
        send_close(server, CloseCode.CLOSE_CODE_NORMAL_CLOSURE)


fn test_client_sends_close_after_connection_is_closed() raises:
    """Test that client cannot send close frame after connection is closed."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_eof(client)
    with assert_raises(contains="InvalidState: connection is not open but 3"):
        send_close[gen_mask_func=gen_mask](client, CloseCode.CLOSE_CODE_GOING_AWAY)


fn test_server_sends_close_after_connection_is_closed() raises:
    """Test that server cannot send close frame after connection is closed."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_eof(server)
    with assert_raises(contains="InvalidState: connection is not open but 3"):
        send_close(server, CloseCode.CLOSE_CODE_NORMAL_CLOSURE)


# ===-------------------------------------------------------------------===#
# Test ping. See 5.5.2. Ping in RFC 6455.
# ===-------------------------------------------------------------------===#


fn test_client_sends_ping() raises:
    """Test that client properly sends a ping frame."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    send_ping[gen_mask_func=gen_mask](client, Bytes())
    assert_bytes_equal(
        client.data_to_send(), Bytes(137, 128, 0, 0, 0, 0)
    )  # \x89\x80\x00\x00\x00\x00


fn test_server_sends_ping() raises:
    """Test that server properly sends a ping frame."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    send_ping(server, Bytes())
    assert_bytes_equal(server.data_to_send(), Bytes(137, 0))  # \x89\x00


fn test_client_receives_ping() raises:
    """Test that client properly receives a ping frame and responds with a pong frame.
    """
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data[gen_mask_func=gen_mask](client, Bytes(137, 0))  # \x89\x00
    events = client.events_received()
    assert_equal(events[0][Frame], Frame(OpCode.OP_PING, Bytes()))
    assert_bytes_equal(
        client.data_to_send(),
        Frame(OpCode.OP_PONG, Bytes()).serialize[gen_mask_func=gen_mask](mask=True),
    )


fn test_server_receives_ping() raises:
    """Test that server properly receives a ping frame and responds with a pong frame.
    """
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data[gen_mask_func=gen_mask](
        server, Bytes(137, 128, 0, 68, 136, 204)
    )  # \x89\x80\x00\x44\x88\xcc
    events = server.events_received()
    assert_equal(events[0][Frame], Frame(OpCode.OP_PING, Bytes()))
    assert_bytes_equal(
        server.data_to_send(),
        Frame(OpCode.OP_PONG, Bytes()).serialize[gen_mask_func=gen_mask](mask=False),
    )


fn test_client_sends_ping_with_data() raises:
    """Test that client properly sends a ping frame with data."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    send_ping[gen_mask_func=gen_mask](
        client, Bytes(34, 102, 170, 238)
    )  # \x22\x66\xaa\xee
    assert_bytes_equal(
        client.data_to_send(), Bytes(137, 132, 0, 0, 0, 0, 34, 102, 170, 238)
    )  # \x89\x84\x00\x00\x00\x00\x22\x66\xaa\xee


fn test_server_sends_ping_with_data() raises:
    """Test that server properly sends a ping frame with data."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    send_ping(server, Bytes(34, 102, 170, 238))  # \x22\x66\xaa\xee
    assert_bytes_equal(
        server.data_to_send(), Bytes(137, 4, 34, 102, 170, 238)
    )  # \x89\x04\x22\x66\xaa\xee


fn test_client_receives_ping_with_data() raises:
    """Test that client properly receives a ping frame with data and responds with a pong frame.
    """
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data[gen_mask_func=gen_mask](
        client, Bytes(137, 4, 34, 102, 170, 238)
    )  # \x89\x04\x22\x66\xaa\xee
    events = client.events_received()
    assert_equal(events[0][Frame], Frame(OpCode.OP_PING, Bytes(34, 102, 170, 238)))
    assert_bytes_equal(
        client.data_to_send(),
        Frame(OpCode.OP_PONG, Bytes(34, 102, 170, 238)).serialize[
            gen_mask_func=gen_mask
        ](mask=True),
    )


fn test_server_receives_ping_with_data() raises:
    """Test that server properly receives a ping frame with data and responds with a pong frame.
    """
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data[gen_mask_func=gen_mask](
        server, Bytes(137, 132, 0, 68, 136, 204, 34, 34, 34, 34)
    )  # \x89\x84\x00\x44\x88\xcc\x22\x22\x22\x22
    events = server.events_received()
    assert_equal(events[0][Frame], Frame(OpCode.OP_PING, Bytes(34, 102, 170, 238)))
    assert_bytes_equal(
        server.data_to_send(),
        Frame(OpCode.OP_PONG, Bytes(34, 102, 170, 238)).serialize[
            gen_mask_func=gen_mask
        ](mask=False),
    )


fn test_client_sends_fragmented_ping_frame() raises:
    """Test that client cannot send fragmented ping frames."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    with assert_raises(contains="ProtocolError: fragmented control frame"):
        send_frame[gen_mask_func=gen_mask](
            client, Frame(OpCode.OP_PING, Bytes(), fin=False)
        )


fn test_server_sends_fragmented_ping_frame() raises:
    """Test that server cannot send fragmented ping frames."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    with assert_raises(contains="ProtocolError: fragmented control frame"):
        send_frame(server, Frame(OpCode.OP_PING, Bytes(), fin=False))


fn test_client_receives_fragmented_ping_frame() raises:
    """Test that client properly handles receiving fragmented ping frames."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data(client, Bytes(9, 0))  # \x09\x00
    events = client.events_received()
    assert_equal(
        String(client.parser_exc.value()), "ProtocolError: fragmented control frame"
    )
    assert_equal(
        events[0][Frame],
        Frame(
            OpCode.OP_CLOSE,
            Close(
                CloseCode.CLOSE_CODE_PROTOCOL_ERROR,
                "ProtocolError: fragmented control frame",
            ).serialize(),
            fin=True,
        ),
    )


fn test_server_receives_fragmented_ping_frame() raises:
    """Test that server properly handles receiving fragmented ping frames."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data[gen_mask_func=gen_mask](
        server, Bytes(9, 128, 0, 0, 0, 0)
    )  # \x89\x80\x00\x00\x00\x00
    events = server.events_received()
    assert_equal(
        String(server.parser_exc.value()), "ProtocolError: fragmented control frame"
    )
    assert_equal(
        events[0][Frame],
        Frame(
            OpCode.OP_CLOSE,
            Close(
                CloseCode.CLOSE_CODE_PROTOCOL_ERROR,
                "ProtocolError: fragmented control frame",
            ).serialize(),
            fin=True,
        ),
    )


fn test_client_sends_ping_after_sending_close() raises:
    """Test that client can send ping frames after sending a close frame."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())

    fn gen_mask2() -> Bytes:
        return Bytes(0, 68, 136, 204)

    send_close[gen_mask_func=gen_mask](client, CloseCode.CLOSE_CODE_GOING_AWAY)
    assert_bytes_equal(client.data_to_send(), Bytes(136, 130, 0, 0, 0, 0, 3, 233))

    send_ping[gen_mask_func=gen_mask2](client, Bytes())
    assert_bytes_equal(client.data_to_send(), Bytes(137, 128, 0, 68, 136, 204))


fn test_server_sends_ping_after_sending_close() raises:
    """Test that server can send ping frames after sending a close frame."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    send_close(server, CloseCode.CLOSE_CODE_NORMAL_CLOSURE)
    assert_bytes_equal(server.data_to_send(), Bytes(136, 2, 3, 232))
    send_ping(server, Bytes())
    assert_bytes_equal(server.data_to_send(), Bytes(137, 0))


fn test_client_receives_ping_after_receiving_close() raises:
    """Test that client properly ignores ping frames after receiving a close frame."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())

    # Receive close frame
    receive_data[gen_mask_func=gen_mask](client, Bytes(136, 2, 3, 232))
    events = client.events_received()
    close_frame = Frame(
        OpCode.OP_CLOSE,
        Close(CloseCode.CLOSE_CODE_NORMAL_CLOSURE, "").serialize(),
        fin=True,
    )
    assert_equal(events[0][Frame], close_frame)
    assert_bytes_equal(
        client.data_to_send(), close_frame.serialize[gen_mask_func=gen_mask](mask=True)
    )

    # Receive ping frame after close - should be ignored
    receive_data(client, Bytes(137, 4, 34, 102, 170, 238))
    events = client.events_received()
    assert_equal(len(events), 0)
    assert_bytes_equal(client.data_to_send(), Bytes())


fn test_server_receives_ping_after_receiving_close() raises:
    """Test that server properly ignores ping frames after receiving a close frame."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())

    # Receive close frame
    receive_data[gen_mask_func=gen_mask](server, Bytes(136, 130, 0, 0, 0, 0, 3, 233))
    events = server.events_received()
    close_frame = Frame(
        OpCode.OP_CLOSE,
        Close(CloseCode.CLOSE_CODE_GOING_AWAY, "").serialize(),
        fin=True,
    )
    assert_equal(events[0][Frame], close_frame)
    assert_bytes_equal(
        server.data_to_send(), close_frame.serialize[gen_mask_func=gen_mask](mask=False)
    )

    # Receive ping frame after close - should be ignored
    receive_data[gen_mask_func=gen_mask](
        server, Bytes(137, 132, 0, 68, 136, 204, 34, 34, 34, 34)
    )
    events = server.events_received()
    assert_equal(len(events), 0)
    assert_bytes_equal(server.data_to_send(), Bytes())


fn test_client_sends_ping_after_connection_is_closed() raises:
    """Test that client cannot send ping frames after connection is closed."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_eof(client)
    with assert_raises(contains="InvalidState: connection is 3"):
        send_ping(client, Bytes())


fn test_server_sends_ping_after_connection_is_closed() raises:
    """Test that server cannot send ping frames after connection is closed."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_eof(server)
    with assert_raises(contains="InvalidState: connection is 3"):
        send_ping(server, Bytes())


# ===-------------------------------------------------------------------===#
# Test pong. See 5.5.3. Pong in RFC 6455.
# ===-------------------------------------------------------------------===#


fn test_client_sends_pong() raises:
    """Test that client properly sends a pong frame."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    send_frame[gen_mask_func=gen_mask](client, Frame(OpCode.OP_PONG, Bytes()))
    assert_bytes_equal(
        client.data_to_send(), Bytes(138, 128, 0, 0, 0, 0)
    )  # \x8a\x80\x00\x00\x00\x00


fn test_server_sends_pong() raises:
    """Test that server properly sends a pong frame."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    send_frame(server, Frame(OpCode.OP_PONG, Bytes()))
    assert_bytes_equal(server.data_to_send(), Bytes(138, 0))  # \x8a\x00


fn test_client_receives_pong() raises:
    """Test that client properly receives a pong frame."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data(client, Bytes(138, 0))  # \x8a\x00
    events = client.events_received()
    assert_equal(events[0][Frame], Frame(OpCode.OP_PONG, Bytes()))


fn test_server_receives_pong() raises:
    """Test that server properly receives a pong frame."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data[gen_mask_func=gen_mask](
        server, Bytes(138, 128, 0, 68, 136, 204)
    )  # \x8a\x80\x00\x44\x88\xcc
    events = server.events_received()
    assert_equal(events[0][Frame], Frame(OpCode.OP_PONG, Bytes()))


fn test_client_sends_pong_with_data() raises:
    """Test that client properly sends a pong frame with data."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())

    fn gen_mask() -> Bytes:
        return Bytes(0, 68, 136, 204)

    send_frame[gen_mask_func=gen_mask](
        client, Frame(OpCode.OP_PONG, Bytes(34, 102, 170, 238))
    )  # \x22\x66\xaa\xee
    assert_bytes_equal(
        client.data_to_send(), Bytes(138, 132, 0, 68, 136, 204, 34, 34, 34, 34)
    )  # \x8a\x84\x00\x44\x88\xcc\x22\x22\x22\x22


fn test_server_sends_pong_with_data() raises:
    """Test that server properly sends a pong frame with data."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    send_frame(
        server, Frame(OpCode.OP_PONG, Bytes(34, 102, 170, 238))
    )  # \x22\x66\xaa\xee
    assert_bytes_equal(
        server.data_to_send(), Bytes(138, 4, 34, 102, 170, 238)
    )  # \x8a\x04\x22\x66\xaa\xee


fn test_client_receives_pong_with_data() raises:
    """Test that client properly receives a pong frame with data."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data(client, Bytes(138, 4, 34, 102, 170, 238))  # \x8a\x04\x22\x66\xaa\xee
    events = client.events_received()
    assert_equal(events[0][Frame], Frame(OpCode.OP_PONG, Bytes(34, 102, 170, 238)))


fn test_server_receives_pong_with_data() raises:
    """Test that server properly receives a pong frame with data."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data[gen_mask_func=gen_mask](
        server, Bytes(138, 132, 0, 68, 136, 204, 34, 34, 34, 34)
    )  # \x8a\x84\x00\x44\x88\xcc\x22\x22\x22\x22
    events = server.events_received()
    assert_equal(events[0][Frame], Frame(OpCode.OP_PONG, Bytes(34, 102, 170, 238)))


fn test_client_sends_fragmented_pong_frame() raises:
    """Test that client cannot send fragmented pong frames."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    with assert_raises(contains="ProtocolError: fragmented control frame"):
        send_frame[gen_mask_func=gen_mask](
            client, Frame(OpCode.OP_PONG, Bytes(), fin=False)
        )


fn test_server_sends_fragmented_pong_frame() raises:
    """Test that server cannot send fragmented pong frames."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    with assert_raises(contains="ProtocolError: fragmented control frame"):
        send_frame(server, Frame(OpCode.OP_PONG, Bytes(), fin=False))


fn test_client_receives_fragmented_pong_frame() raises:
    """Test that client properly handles receiving fragmented pong frames."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data(client, Bytes(10, 0))  # \x0a\x00
    events = client.events_received()
    assert_equal(
        String(client.parser_exc.value()), "ProtocolError: fragmented control frame"
    )
    assert_equal(
        events[0][Frame],
        Frame(
            OpCode.OP_CLOSE,
            Close(
                CloseCode.CLOSE_CODE_PROTOCOL_ERROR,
                "ProtocolError: fragmented control frame",
            ).serialize(),
            fin=True,
        ),
    )


fn test_server_receives_fragmented_pong_frame() raises:
    """Test that server properly handles receiving fragmented pong frames."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data[gen_mask_func=gen_mask](
        server, Bytes(10, 128, 0, 0, 0, 0)
    )  # \x8a\x80\x00\x00\x00\x00
    events = server.events_received()
    assert_equal(
        String(server.parser_exc.value()), "ProtocolError: fragmented control frame"
    )
    assert_equal(
        events[0][Frame],
        Frame(
            OpCode.OP_CLOSE,
            Close(
                CloseCode.CLOSE_CODE_PROTOCOL_ERROR,
                "ProtocolError: fragmented control frame",
            ).serialize(),
            fin=True,
        ),
    )


fn test_client_sends_pong_after_sending_close() raises:
    """Test that client can send pong frames after sending a close frame."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())

    fn gen_mask2() -> Bytes:
        return Bytes(0, 68, 136, 204)

    send_close[gen_mask_func=gen_mask](client, CloseCode.CLOSE_CODE_GOING_AWAY)
    assert_bytes_equal(client.data_to_send(), Bytes(136, 130, 0, 0, 0, 0, 3, 233))

    send_frame[gen_mask_func=gen_mask2](client, Frame(OpCode.OP_PONG, Bytes()))
    assert_bytes_equal(client.data_to_send(), Bytes(138, 128, 0, 68, 136, 204))


fn test_server_sends_pong_after_sending_close() raises:
    """Test that server can send pong frames after sending a close frame."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    send_close(server, CloseCode.CLOSE_CODE_NORMAL_CLOSURE)
    assert_bytes_equal(server.data_to_send(), Bytes(136, 2, 3, 232))
    send_frame(server, Frame(OpCode.OP_PONG, Bytes()))
    assert_bytes_equal(server.data_to_send(), Bytes(138, 0))


fn test_client_receives_pong_after_receiving_close() raises:
    """Test that client properly ignores pong frames after receiving a close frame."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())

    # Receive close frame
    receive_data[gen_mask_func=gen_mask](client, Bytes(136, 2, 3, 232))
    events = client.events_received()
    close_frame = Frame(
        OpCode.OP_CLOSE,
        Close(CloseCode.CLOSE_CODE_NORMAL_CLOSURE, "").serialize(),
        fin=True,
    )
    assert_equal(events[0][Frame], close_frame)
    assert_bytes_equal(
        client.data_to_send(), close_frame.serialize[gen_mask_func=gen_mask](mask=True)
    )

    # Receive pong frame after close - should be ignored
    receive_data(client, Bytes(138, 4, 34, 102, 170, 238))
    events = client.events_received()
    assert_equal(len(events), 0)
    assert_bytes_equal(client.data_to_send(), Bytes())


fn test_server_receives_pong_after_receiving_close() raises:
    """Test that server properly ignores pong frames after receiving a close frame."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())

    # Receive close frame
    receive_data[gen_mask_func=gen_mask](server, Bytes(136, 130, 0, 0, 0, 0, 3, 233))
    events = server.events_received()
    close_frame = Frame(
        OpCode.OP_CLOSE,
        Close(CloseCode.CLOSE_CODE_GOING_AWAY, "").serialize(),
        fin=True,
    )
    assert_equal(events[0][Frame], close_frame)
    assert_bytes_equal(
        server.data_to_send(), close_frame.serialize[gen_mask_func=gen_mask](mask=False)
    )

    # Receive pong frame after close - should be ignored
    receive_data[gen_mask_func=gen_mask](
        server, Bytes(138, 132, 0, 68, 136, 204, 34, 34, 34, 34)
    )
    events = server.events_received()
    assert_equal(len(events), 0)
    assert_bytes_equal(server.data_to_send(), Bytes())


fn test_client_sends_pong_after_connection_is_closed() raises:
    """Test that client cannot send pong frames after connection is closed."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_eof(client)
    with assert_raises(contains="InvalidState: connection is closed"):
        send_frame(client, Frame(OpCode.OP_PONG, Bytes()))


fn test_server_sends_pong_after_connection_is_closed() raises:
    """Test that server cannot send pong frames after connection is closed."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_eof(server)
    with assert_raises(contains="InvalidState: connection is closed"):
        send_frame(server, Frame(OpCode.OP_PONG, Bytes()))


# ===-------------------------------------------------------------------===#
# Test failing the connection.
# See 7.1.7. Fail the WebSocket Connection in RFC 6455.
# ===-------------------------------------------------------------------===#


fn test_client_stops_processing_frames_after_fail() raises:
    """Test that client stops processing frames after connection failure."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())

    # Fail the connection with protocol error
    fail[gen_mask_func=gen_mask](client, CloseCode.CLOSE_CODE_PROTOCOL_ERROR)
    events = client.events_received()
    assert_equal(len(events), 0)
    data_to_send = client.data_to_send()
    # assert_equal(String(client.parser_exc.value()), "ProtocolError: invalid close code")
    close_frame = Frame(
        OpCode.OP_CLOSE,
        Close(CloseCode.CLOSE_CODE_PROTOCOL_ERROR, "").serialize(),
        fin=True,
    )
    assert_bytes_equal(
        data_to_send, close_frame.serialize[gen_mask_func=gen_mask](mask=True)
    )

    # Try to receive more data after failure - should be ignored
    receive_data(client, Bytes(136, 2, 3, 234))  # \x88\x02\x03\xea
    events = client.events_received()
    assert_equal(len(events), 0)
    assert_bytes_equal(client.data_to_send(), Bytes())


fn test_server_stops_processing_frames_after_fail() raises:
    """Test that server stops processing frames after connection failure."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())

    # Fail the connection with protocol error
    fail[gen_mask_func=gen_mask](server, CloseCode.CLOSE_CODE_PROTOCOL_ERROR)
    events = server.events_received()
    assert_equal(len(events), 0)
    data_to_send = server.data_to_send()
    close_frame = Frame(
        OpCode.OP_CLOSE,
        Close(CloseCode.CLOSE_CODE_PROTOCOL_ERROR, "").serialize(),
        fin=True,
    )
    assert_bytes_equal(
        data_to_send, close_frame.serialize[gen_mask_func=gen_mask](mask=False)
    )

    # Try to receive more data after failure - should be ignored
    receive_data[gen_mask_func=gen_mask](
        server, Bytes(136, 130, 0, 0, 0, 0, 3, 234)
    )  # \x88\x82\x00\x00\x00\x00\x03\xea
    events = server.events_received()
    assert_equal(len(events), 0)
    assert_bytes_equal(server.data_to_send(), Bytes())


# ===-------------------------------------------------------------------===#
# Test message fragmentation.
# See 5.4. Fragmentation in RFC 6455.
# ===-------------------------------------------------------------------===#


fn test_client_send_ping_pong_in_fragmented_message() raises:
    """Test that client can send ping/pong frames within a fragmented message."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())

    # Send initial text frame
    send_text[gen_mask_func=gen_mask](client, str_to_bytes("Spam"), fin=False)
    assert_bytes_equal(
        client.data_to_send(), Bytes(1, 132, 0, 0, 0, 0) + str_to_bytes("Spam")
    )

    # Send ping frame
    send_ping[gen_mask_func=gen_mask](client, str_to_bytes("Ping"))
    assert_bytes_equal(
        client.data_to_send(), Bytes(137, 132, 0, 0, 0, 0) + str_to_bytes("Ping")
    )

    # Send continuation frame
    send_continuation[gen_mask_func=gen_mask](client, str_to_bytes("Ham"), fin=False)
    assert_bytes_equal(
        client.data_to_send(), Bytes(0, 131, 0, 0, 0, 0) + str_to_bytes("Ham")
    )

    # Send pong frame
    send_frame[gen_mask_func=gen_mask](
        client, Frame(OpCode.OP_PONG, str_to_bytes("Pong"))
    )
    assert_bytes_equal(
        client.data_to_send(), Bytes(138, 132, 0, 0, 0, 0) + str_to_bytes("Pong")
    )

    # Send final continuation frame
    send_continuation[gen_mask_func=gen_mask](client, str_to_bytes("Eggs"), fin=True)
    assert_bytes_equal(
        client.data_to_send(), Bytes(128, 132, 0, 0, 0, 0) + str_to_bytes("Eggs")
    )


fn test_server_send_ping_pong_in_fragmented_message() raises:
    """Test that server can send ping/pong frames within a fragmented message."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())

    # Send initial text frame
    send_text(server, str_to_bytes("Spam"), fin=False)
    assert_bytes_equal(server.data_to_send(), Bytes(1, 4) + str_to_bytes("Spam"))

    # Send ping frame
    send_ping(server, str_to_bytes("Ping"))
    assert_bytes_equal(server.data_to_send(), Bytes(137, 4) + str_to_bytes("Ping"))

    # Send continuation frame
    send_continuation(server, str_to_bytes("Ham"), fin=False)
    assert_bytes_equal(server.data_to_send(), Bytes(0, 3) + str_to_bytes("Ham"))

    # Send pong frame
    send_frame(server, Frame(OpCode.OP_PONG, str_to_bytes("Pong")))
    assert_bytes_equal(server.data_to_send(), Bytes(138, 4) + str_to_bytes("Pong"))

    # Send final continuation frame
    send_continuation(server, str_to_bytes("Eggs"), fin=True)
    assert_bytes_equal(server.data_to_send(), Bytes(128, 4) + str_to_bytes("Eggs"))


fn test_client_receive_ping_pong_in_fragmented_message() raises:
    """Test that client properly handles ping/pong frames within a fragmented message.
    """
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())

    # Receive initial text frame
    receive_data[gen_mask_func=gen_mask](
        client, Bytes(1, 4) + str_to_bytes("Spam")
    )  # \x01\x04Spam
    events = client.events_received()
    assert_equal(
        events[0][Frame], Frame(OpCode.OP_TEXT, str_to_bytes("Spam"), fin=False)
    )

    # Receive ping frame
    receive_data[gen_mask_func=gen_mask](
        client, Bytes(137, 4) + str_to_bytes("Ping")
    )  # \x89\x04Ping
    events = client.events_received()
    assert_equal(events[0][Frame], Frame(OpCode.OP_PING, str_to_bytes("Ping")))
    assert_bytes_equal(
        client.data_to_send(),
        Frame(OpCode.OP_PONG, str_to_bytes("Ping")).serialize[gen_mask_func=gen_mask](
            mask=True
        ),
    )

    # Receive continuation frame
    receive_data(client, Bytes(0, 3) + str_to_bytes("Ham"))  # \x00\x03Ham
    events = client.events_received()
    assert_equal(
        events[0][Frame], Frame(OpCode.OP_CONT, str_to_bytes("Ham"), fin=False)
    )

    # Receive pong frame
    receive_data(client, Bytes(138, 4) + str_to_bytes("Pong"))  # \x8a\x04Pong
    events = client.events_received()
    assert_equal(events[0][Frame], Frame(OpCode.OP_PONG, str_to_bytes("Pong")))

    # Receive final continuation frame
    receive_data(client, Bytes(128, 4) + str_to_bytes("Eggs"))  # \x80\x04Eggs
    events = client.events_received()
    assert_equal(events[0][Frame], Frame(OpCode.OP_CONT, str_to_bytes("Eggs")))


fn test_server_receive_ping_pong_in_fragmented_message() raises:
    """Test that server properly handles ping/pong frames within a fragmented message.
    """
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())

    # Receive initial text frame
    receive_data[gen_mask_func=gen_mask](
        server, Bytes(1, 132, 0, 0, 0, 0) + str_to_bytes("Spam")
    )  # \x01\x84\x00\x00\x00\x00Spam
    events = server.events_received()
    assert_equal(
        events[0][Frame], Frame(OpCode.OP_TEXT, str_to_bytes("Spam"), fin=False)
    )

    # Receive ping frame
    receive_data[gen_mask_func=gen_mask](
        server, Bytes(137, 132, 0, 0, 0, 0) + str_to_bytes("Ping")
    )  # \x89\x84\x00\x00\x00\x00Ping
    events = server.events_received()
    assert_equal(events[0][Frame], Frame(OpCode.OP_PING, str_to_bytes("Ping")))
    assert_bytes_equal(
        server.data_to_send(),
        Frame(OpCode.OP_PONG, str_to_bytes("Ping")).serialize[gen_mask_func=gen_mask](
            mask=False
        ),
    )

    # Receive continuation frame
    receive_data[gen_mask_func=gen_mask](
        server, Bytes(0, 131, 0, 0, 0, 0) + str_to_bytes("Ham")
    )  # \x00\x83\x00\x00\x00\x00Ham
    events = server.events_received()
    assert_equal(
        events[0][Frame], Frame(OpCode.OP_CONT, str_to_bytes("Ham"), fin=False)
    )

    # Receive pong frame
    receive_data[gen_mask_func=gen_mask](
        server, Bytes(138, 132, 0, 0, 0, 0) + str_to_bytes("Pong")
    )  # \x8a\x84\x00\x00\x00\x00Pong
    events = server.events_received()
    assert_equal(events[0][Frame], Frame(OpCode.OP_PONG, str_to_bytes("Pong")))

    # Receive final continuation frame
    receive_data[gen_mask_func=gen_mask](
        server, Bytes(128, 132, 0, 0, 0, 0) + str_to_bytes("Eggs")
    )  # \x80\x84\x00\x00\x00\x00Eggs
    events = server.events_received()
    assert_equal(events[0][Frame], Frame(OpCode.OP_CONT, str_to_bytes("Eggs")))


fn test_client_send_close_in_fragmented_message() raises:
    """Test that client cannot send close frame in a fragmented message."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())

    fn gen_mask() -> Bytes:
        return Bytes(60, 60, 60, 60)

    # Send initial text frame
    send_text[gen_mask_func=gen_mask](client, str_to_bytes("Spam"), fin=False)
    assert_bytes_equal(
        client.data_to_send(), Bytes(1, 132, 60, 60, 60, 60, 111, 76, 93, 81)
    )

    # Try to send close frame - should fail
    send_close[gen_mask_func=gen_mask](client)
    assert_bytes_equal(client.data_to_send(), Bytes(136, 128, 60, 60, 60, 60))
    assert_equal(client.get_state(), 2)  # CLOSING

    # Try to send continuation frame - should fail
    with assert_raises(contains="InvalidState: connection is not open"):
        send_continuation[gen_mask_func=gen_mask](
            client, str_to_bytes("Eggs"), fin=True
        )


fn test_server_send_close_in_fragmented_message() raises:
    """Test that server cannot send close frame in a fragmented message."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())

    # Send initial text frame
    send_text(server, str_to_bytes("Spam"), fin=False)
    assert_bytes_equal(server.data_to_send(), Bytes(1, 4) + str_to_bytes("Spam"))

    # Try to send close frame - should fail
    send_close(server)
    assert_bytes_equal(server.data_to_send(), Bytes(136, 0))
    assert_equal(server.get_state(), 2)  # CLOSING

    # Try to send continuation frame - should fail
    with assert_raises(contains="InvalidState: connection is not open"):
        send_continuation(server, str_to_bytes("Eggs"), fin=True)


fn test_client_receive_close_in_fragmented_message() raises:
    """Test that client properly handles receiving close frame in a fragmented message.
    """
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())

    # Receive initial text frame
    receive_data(client, Bytes(1, 4) + str_to_bytes("Spam"))  # \x01\x04Spam
    events = client.events_received()
    assert_equal(
        events[0][Frame], Frame(OpCode.OP_TEXT, str_to_bytes("Spam"), fin=False)
    )

    # Receive close frame
    receive_data(client, Bytes(136, 2, 3, 232))  # \x88\x02\x03\xe8
    events = client.events_received()
    assert_equal(
        String(client.parser_exc.value()),
        "ProtocolError: incomplete fragmented message",
    )
    assert_equal(
        events[0][Frame],
        Frame(
            OpCode.OP_CLOSE,
            Close(
                CloseCode.CLOSE_CODE_PROTOCOL_ERROR,
                "ProtocolError: incomplete fragmented message",
            ).serialize(),
            fin=True,
        ),
    )


fn test_server_receive_close_in_fragmented_message() raises:
    """Test that server properly handles receiving close frame in a fragmented message.
    """
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())

    # Receive initial text frame
    receive_data[gen_mask_func=gen_mask](
        server, Bytes(1, 132, 0, 0, 0, 0) + str_to_bytes("Spam")
    )  # \x01\x84\x00\x00\x00\x00Spam
    events = server.events_received()
    assert_equal(
        events[0][Frame], Frame(OpCode.OP_TEXT, str_to_bytes("Spam"), fin=False)
    )

    # Receive close frame
    receive_data[gen_mask_func=gen_mask](
        server, Bytes(136, 130, 0, 0, 0, 0, 3, 233)
    )  # \x88\x82\x00\x00\x00\x00\x03\xe9
    events = server.events_received()
    assert_equal(
        String(server.parser_exc.value()),
        "ProtocolError: incomplete fragmented message",
    )
    assert_equal(
        events[0][Frame],
        Frame(
            OpCode.OP_CLOSE,
            Close(
                CloseCode.CLOSE_CODE_PROTOCOL_ERROR,
                "ProtocolError: incomplete fragmented message",
            ).serialize(),
            fin=True,
        ),
    )


# ===-------------------------------------------------------------------===#
# Test half-closes on connection termination.
# ===-------------------------------------------------------------------===#


fn test_client_receives_eof() raises:
    """Test that client properly handles receiving EOF after close frame."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())

    # Receive close frame
    receive_data[gen_mask_func=gen_mask](client, Bytes(136, 0))  # \x88\x00
    events = client.events_received()
    close_frame = Frame(OpCode.OP_CLOSE, Bytes(), fin=True)
    assert_equal(events[0][Frame], close_frame)
    expected = close_frame.serialize[gen_mask_func=gen_mask](mask=True)
    data_to_send = client.data_to_send()
    assert_bytes_equal(data_to_send, expected)
    assert_equal(client.get_state(), 2)  # CLOSING

    # Receive EOF
    receive_eof(client)
    assert_equal(client.get_state(), 3)  # CLOSED


fn test_server_receives_eof() raises:
    """Test that server properly handles receiving EOF after close frame."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())

    # Receive close frame
    receive_data[gen_mask_func=gen_mask](
        server, Bytes(136, 128, 60, 60, 60, 60)
    )  # \x88\x80\x3c\x3c\x3c\x3c
    events = server.events_received()
    close_frame = Frame(OpCode.OP_CLOSE, Bytes(), fin=True)
    assert_equal(events[0][Frame], close_frame)
    assert_bytes_equal(
        server.data_to_send(), close_frame.serialize[gen_mask_func=gen_mask](mask=False)
    )
    assert_equal(server.get_state(), 2)  # CLOSING

    # Receive EOF
    receive_eof(server)
    assert_equal(server.get_state(), 3)  # CLOSED


fn test_client_receives_eof_between_frames() raises:
    """Test that client properly handles receiving EOF between frames."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())

    # Receive EOF between frames
    receive_eof(client)
    assert_equal(
        String(client.parser_exc.value()),
        "EOFError: stream ends after 0 bytes, expected 2 bytes",
    )
    assert_equal(client.get_state(), 3)  # CLOSED


fn test_server_receives_eof_between_frames() raises:
    """Test that server properly handles receiving EOF between frames."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())

    # Receive EOF between frames
    receive_eof(server)
    assert_equal(
        String(server.parser_exc.value()),
        "EOFError: stream ends after 0 bytes, expected 2 bytes",
    )
    assert_equal(server.get_state(), 3)  # CLOSED


fn test_client_receives_eof_inside_frame() raises:
    """Test that client properly handles receiving EOF inside a frame."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())

    # Receive partial frame
    receive_data(client, Bytes(129))  # \x81

    # Receive EOF
    receive_eof(client)

    assert_equal(
        String(client.parser_exc.value()),
        "EOFError: stream ends after 1 bytes, expected 2 bytes",
    )
    assert_equal(client.get_state(), 3)  # CLOSED


fn test_server_receives_eof_inside_frame() raises:
    """Test that server properly handles receiving EOF inside a frame."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())

    # Receive partial frame
    receive_data(server, Bytes(129))  # \x81

    # Receive EOF
    receive_eof(server)

    assert_equal(
        String(server.parser_exc.value()),
        "EOFError: stream ends after 1 bytes, expected 2 bytes",
    )
    assert_equal(server.get_state(), 3)  # CLOSED


fn test_client_receives_data_after_exception() raises:
    """Test that client properly handles receiving data after an exception."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())

    # Receive invalid frame
    receive_data[gen_mask_func=gen_mask](client, Bytes(255, 255))  # \xff\xff
    events = client.events_received()
    assert_equal(String(client.parser_exc.value()), "ProtocolError: invalid opcode: 15")
    close_frame = Frame(
        OpCode.OP_CLOSE,
        Close(
            CloseCode.CLOSE_CODE_PROTOCOL_ERROR, "ProtocolError: invalid opcode: 15"
        ).serialize(),
        fin=True,
    )
    assert_equal(events[0][Frame], close_frame)
    data_to_send = client.data_to_send()
    assert_bytes_equal(
        data_to_send, close_frame.serialize[gen_mask_func=gen_mask](mask=True)
    )

    # Try to receive more data after exception
    receive_data(client, Bytes(0, 0))  # \x00\x00
    events = client.events_received()
    assert_equal(len(events), 0)
    assert_bytes_equal(client.data_to_send(), Bytes())


fn test_server_receives_data_after_exception() raises:
    """Test that server properly handles receiving data after an exception."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())

    # Receive invalid frame
    receive_data[gen_mask_func=gen_mask](server, Bytes(255, 255))  # \xff\xff
    events = server.events_received()
    assert_equal(String(server.parser_exc.value()), "ProtocolError: invalid opcode: 15")
    close_frame = Frame(
        OpCode.OP_CLOSE,
        Close(
            CloseCode.CLOSE_CODE_PROTOCOL_ERROR, "ProtocolError: invalid opcode: 15"
        ).serialize(),
        fin=True,
    )
    assert_equal(events[0][Frame], close_frame)
    data_to_send = server.data_to_send()
    assert_bytes_equal(
        data_to_send, close_frame.serialize[gen_mask_func=gen_mask](mask=False)
    )

    # Try to receive more data after exception
    receive_data[gen_mask_func=gen_mask](server, Bytes(0, 0))  # \x00\x00
    events = server.events_received()
    assert_equal(len(events), 0)
    assert_bytes_equal(server.data_to_send(), Bytes())


fn test_client_receives_eof_after_exception() raises:
    """Test that client properly handles receiving EOF after an exception."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())

    # Receive invalid frame
    receive_data[gen_mask_func=gen_mask](client, Bytes(255, 255))  # \xff\xff
    events = client.events_received()
    assert_equal(String(client.parser_exc.value()), "ProtocolError: invalid opcode: 15")
    close_frame = Frame(
        OpCode.OP_CLOSE,
        Close(
            CloseCode.CLOSE_CODE_PROTOCOL_ERROR, "ProtocolError: invalid opcode: 15"
        ).serialize(),
        fin=True,
    )
    assert_equal(events[0][Frame], close_frame)
    data_to_send = client.data_to_send()
    assert_bytes_equal(
        data_to_send, close_frame.serialize[gen_mask_func=gen_mask](mask=True)
    )

    # Receive EOF after exception
    receive_eof(client)
    assert_bytes_equal(client.data_to_send(), Bytes())
    assert_equal(client.get_state(), 3)  # CLOSED


fn test_server_receives_eof_after_exception() raises:
    """Test that server properly handles receiving EOF after an exception."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())

    # Receive invalid frame
    receive_data[gen_mask_func=gen_mask](server, Bytes(255, 255))  # \xff\xff
    events = server.events_received()
    assert_equal(String(server.parser_exc.value()), "ProtocolError: invalid opcode: 15")
    close_frame = Frame(
        OpCode.OP_CLOSE,
        Close(
            CloseCode.CLOSE_CODE_PROTOCOL_ERROR, "ProtocolError: invalid opcode: 15"
        ).serialize(),
        fin=True,
    )
    assert_equal(events[0][Frame], close_frame)
    data_to_send = server.data_to_send()
    assert_bytes_equal(data_to_send, close_frame.serialize(mask=False))

    # Receive EOF after exception
    receive_eof(server)
    assert_bytes_equal(server.data_to_send(), Bytes())
    assert_equal(server.get_state(), 3)  # CLOSED


fn test_client_receives_data_and_eof_after_exception() raises:
    """Test that client properly handles receiving data and EOF after an exception."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())

    # Receive invalid frame
    receive_data[gen_mask_func=gen_mask](client, Bytes(255, 255))  # \xff\xff
    events = client.events_received()
    assert_equal(String(client.parser_exc.value()), "ProtocolError: invalid opcode: 15")
    close_frame = Frame(
        OpCode.OP_CLOSE,
        Close(
            CloseCode.CLOSE_CODE_PROTOCOL_ERROR, "ProtocolError: invalid opcode: 15"
        ).serialize(),
        fin=True,
    )
    assert_equal(events[0][Frame], close_frame)
    data_to_send = client.data_to_send()
    expected_data = close_frame.serialize[gen_mask_func=gen_mask](mask=True)
    assert_bytes_equal(data_to_send, expected_data)

    # Receive more data after exception
    receive_data(client, Bytes(0, 0))  # \x00\x00
    events = client.events_received()
    assert_equal(len(events), 0)
    assert_bytes_equal(client.data_to_send(), Bytes())

    # Receive EOF after data
    receive_eof(client)
    assert_bytes_equal(client.data_to_send(), Bytes())
    assert_equal(client.get_state(), 3)  # CLOSED


fn test_server_receives_data_and_eof_after_exception() raises:
    """Test that server properly handles receiving data and EOF after an exception."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())

    # Receive invalid frame
    receive_data[gen_mask_func=gen_mask](server, Bytes(255, 255))  # \xff\xff
    events = server.events_received()
    assert_equal(String(server.parser_exc.value()), "ProtocolError: invalid opcode: 15")
    close_frame = Frame(
        OpCode.OP_CLOSE,
        Close(
            CloseCode.CLOSE_CODE_PROTOCOL_ERROR, "ProtocolError: invalid opcode: 15"
        ).serialize(),
        fin=True,
    )
    assert_equal(events[0][Frame], close_frame)
    data_to_send = server.data_to_send()
    assert_bytes_equal(
        data_to_send, close_frame.serialize[gen_mask_func=gen_mask](mask=False)
    )

    # Receive more data after exception
    receive_data[gen_mask_func=gen_mask](server, Bytes(0, 0))  # \x00\x00
    events = server.events_received()
    assert_equal(len(events), 0)
    assert_bytes_equal(server.data_to_send(), Bytes())

    # Receive EOF after data
    receive_eof(server)
    assert_bytes_equal(server.data_to_send(), Bytes())
    assert_equal(server.get_state(), 3)  # CLOSED


fn test_client_receives_data_after_eof() raises:
    """Test that client properly handles receiving data after EOF."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())

    # Receive close frame
    receive_data(client, Bytes(136, 0))  # \x88\x00
    assert_equal(client.get_state(), 2)  # CLOSING

    # Receive EOF
    receive_eof(client)

    # Try to receive data after EOF - should raise EOFError
    with assert_raises(contains="EOFError: stream ended"):
        receive_data(client, Bytes(136, 0))  # \x88\x00


fn test_server_receives_data_after_eof() raises:
    """Test that server properly handles receiving data after EOF."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())

    # Receive close frame
    receive_data[gen_mask_func=gen_mask](
        server, Bytes(136, 128, 60, 60, 60, 60)
    )  # \x88\x80\x3c\x3c\x3c\x3c
    assert_equal(server.get_state(), 2)  # CLOSING

    # Receive EOF
    receive_eof(server)

    # Try to receive data after EOF - should raise EOFError
    with assert_raises(contains="EOFError: stream ended"):
        receive_data[gen_mask_func=gen_mask](
            server, Bytes(136, 128, 0, 0, 0, 0)
        )  # \x88\x80\x00\x00\x00\x00


fn test_client_receives_eof_after_eof() raises:
    """Test that client properly handles receiving EOF after EOF (should be idempotent).
    """
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())

    # Receive close frame
    receive_data(client, Bytes(136, 0))  # \x88\x00
    assert_equal(client.get_state(), 2)  # CLOSING

    # Receive EOF twice - should be idempotent
    receive_eof(client)
    receive_eof(client)  # This should not raise any error


fn test_server_receives_eof_after_eof() raises:
    """Test that server properly handles receiving EOF after EOF (should be idempotent).
    """
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())

    # Receive close frame
    receive_data[gen_mask_func=gen_mask](
        server, Bytes(136, 128, 60, 60, 60, 60)
    )  # \x88\x80\x3c\x3c\x3c\x3c
    assert_equal(server.get_state(), 2)  # CLOSING

    # Receive EOF twice - should be idempotent
    receive_eof(server)
    receive_eof(server)  # This should not raise any error


# ===-------------------------------------------------------------------===#
# Test expectation of TCP close on connection termination.
# ===-------------------------------------------------------------------===#


fn test_client_default() raises:
    """Test that client does not expect close by default."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    assert_equal(close_expected(client), False)


fn test_server_default() raises:
    """Test that server does not expect close by default."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    assert_equal(close_expected(server), False)


fn test_close_expected_if_client_sends_close() raises:
    """Test that client expects close after sending close frame."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    send_close[gen_mask_func=gen_mask](client)
    assert_equal(close_expected(client), True)


fn test_close_expected_if_server_sends_close() raises:
    """Test that server expects close after sending close frame."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    send_close(server)
    assert_equal(close_expected(server), True)


fn test_close_expected_if_client_receives_close() raises:
    """Test that client expects close after receiving close frame."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data(client, Bytes(136, 0))  # \x88\x00
    assert_equal(close_expected(client), True)


fn test_close_expected_if_client_receives_close_then_eof() raises:
    """Test that client does not expect close after receiving close frame and EOF."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data(client, Bytes(136, 0))  # \x88\x00
    receive_eof(client)
    assert_equal(close_expected(client), False)


fn test_close_expected_if_server_receives_close_then_eof() raises:
    """Test that server does not expect close after receiving close frame and EOF."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data[gen_mask_func=gen_mask](
        server, Bytes(136, 128, 60, 60, 60, 60)
    )  # \x88\x80\x3c\x3c\x3c\x3c
    receive_eof(server)
    assert_equal(close_expected(server), False)


fn test_close_expected_if_server_receives_close() raises:
    """Test that server expects close after receiving close frame."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_data[gen_mask_func=gen_mask](
        server, Bytes(136, 128, 60, 60, 60, 60)
    )  # \x88\x80\x3c\x3c\x3c\x3c
    assert_equal(close_expected(server), True)


fn test_close_expected_if_client_fails_connection() raises:
    """Test that client expects close after failing the connection."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    fail(client, CloseCode.CLOSE_CODE_PROTOCOL_ERROR)
    assert_equal(close_expected(client), True)


fn test_close_expected_if_server_fails_connection() raises:
    """Test that server expects close after failing the connection."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    fail(server, CloseCode.CLOSE_CODE_PROTOCOL_ERROR)
    assert_equal(close_expected(server), True)


# ===-------------------------------------------------------------------===#
# Test connection closed exception.
# ===-------------------------------------------------------------------===#


fn test_close_exc_if_client_sends_close_then_receives_close() raises:
    """Test client-initiated close handshake on the client side complete."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())

    # Send close frame
    send_close(client, CloseCode.CLOSE_CODE_NORMAL_CLOSURE, "")

    # Receive close frame
    receive_data(client, Bytes(136, 2, 3, 232))  # \x88\x02\x03\xe8

    # Receive EOF
    receive_eof(client)

    # Verify close details
    assert_equal(
        client.get_close_rcvd().value().code, CloseCode.CLOSE_CODE_NORMAL_CLOSURE
    )
    assert_equal(client.get_close_rcvd().value().reason, "")
    assert_equal(
        client.get_close_sent().value().code, CloseCode.CLOSE_CODE_NORMAL_CLOSURE
    )
    assert_equal(client.get_close_sent().value().reason, "")
    assert_equal(client.get_close_rcvd_then_sent().value(), False)

    close_exc = get_close_exc(client)
    assert_equal(String(close_exc), "ConnectionClosedOK: 1000, 1000")


fn test_close_exc_if_server_sends_close_then_receives_close() raises:
    """Test server-initiated close handshake on the server side complete."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())

    # Send close frame
    send_close[gen_mask_func=gen_mask](server, CloseCode.CLOSE_CODE_NORMAL_CLOSURE, "")

    # Receive close frame
    receive_data[gen_mask_func=gen_mask](
        server, Bytes(136, 130, 0, 0, 0, 0, 3, 232)
    )  # \x88\x82\x00\x00\x00\x00\x03\xe8

    # Receive EOF
    receive_eof(server)

    # Verify close details
    assert_equal(
        server.get_close_rcvd().value().code, CloseCode.CLOSE_CODE_NORMAL_CLOSURE
    )
    assert_equal(server.get_close_rcvd().value().reason, "")
    assert_equal(
        server.get_close_sent().value().code, CloseCode.CLOSE_CODE_NORMAL_CLOSURE
    )
    assert_equal(server.get_close_sent().value().reason, "")
    assert_equal(server.get_close_rcvd_then_sent().value(), False)

    close_exc = get_close_exc(server)
    assert_equal(String(close_exc), "ConnectionClosedOK: 1000, 1000")


fn test_close_exc_if_client_receives_close_then_sends_close() raises:
    """Test server-initiated close handshake on the client side complete."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())

    # Receive close frame
    receive_data(client, Bytes(136, 2, 3, 232))  # \x88\x02\x03\xe8

    # Receive EOF
    receive_eof(client)

    # Verify close details
    assert_equal(
        client.get_close_rcvd().value().code, CloseCode.CLOSE_CODE_NORMAL_CLOSURE
    )
    assert_equal(client.get_close_rcvd().value().reason, "")
    assert_equal(
        client.get_close_sent().value().code, CloseCode.CLOSE_CODE_NORMAL_CLOSURE
    )
    assert_equal(client.get_close_sent().value().reason, "")
    assert_equal(client.get_close_rcvd_then_sent().value(), True)

    close_exc = get_close_exc(client)
    assert_equal(String(close_exc), "ConnectionClosedOK: 1000, 1000")


fn test_close_exc_if_server_receives_close_then_sends_close() raises:
    """Test client-initiated close handshake on the server side complete."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())

    fn gen_mask() -> Bytes:
        return Bytes(0, 0, 0, 0)

    # Receive close frame
    receive_data[gen_mask_func=gen_mask](
        server, Bytes(136, 130, 0, 0, 0, 0, 3, 232)
    )  # \x88\x82\x00\x00\x00\x00\x03\xe8

    # Receive EOF
    receive_eof(server)

    # Verify close details
    assert_equal(
        server.get_close_rcvd().value().code, CloseCode.CLOSE_CODE_NORMAL_CLOSURE
    )
    assert_equal(server.get_close_rcvd().value().reason, "")
    assert_equal(
        server.get_close_sent().value().code, CloseCode.CLOSE_CODE_NORMAL_CLOSURE
    )
    assert_equal(server.get_close_sent().value().reason, "")
    assert_equal(server.get_close_rcvd_then_sent().value(), True)

    close_exc = get_close_exc(server)
    assert_equal(String(close_exc), "ConnectionClosedOK: 1000, 1000")


fn test_close_exc_if_client_sends_close_then_receives_eof() raises:
    """Test client-initiated close handshake on the client side times out."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())

    fn gen_mask() -> Bytes:
        return Bytes(0, 0, 0, 0)

    send_close[gen_mask_func=gen_mask](client, CloseCode.CLOSE_CODE_NORMAL_CLOSURE, "")
    receive_eof(client)

    # Verify close details
    assert_equal(Bool(client.get_close_rcvd()), False)
    assert_equal(
        client.get_close_sent().value().code, CloseCode.CLOSE_CODE_NORMAL_CLOSURE
    )
    assert_equal(client.get_close_sent().value().reason, "")
    assert_equal(Bool(client.get_close_rcvd_then_sent()), False)

    close_exc = get_close_exc(client)
    assert_equal(String(close_exc), "ConnectionClosedError: False, True, False")


fn test_close_exc_if_server_sends_close_then_receives_eof() raises:
    """Test server-initiated close handshake on the server side times out."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    send_close(server, CloseCode.CLOSE_CODE_NORMAL_CLOSURE, "")
    receive_eof(server)

    # Verify close details
    assert_equal(Bool(server.get_close_rcvd()), False)
    assert_equal(
        server.get_close_sent().value().code, CloseCode.CLOSE_CODE_NORMAL_CLOSURE
    )
    assert_equal(server.get_close_sent().value().reason, "")
    assert_equal(Bool(server.get_close_rcvd_then_sent()), False)

    close_exc = get_close_exc(server)
    assert_equal(String(close_exc), "ConnectionClosedError: False, True, False")


fn test_close_exc_if_client_receives_eof() raises:
    """Test server-initiated close handshake on the client side times out."""
    client = DummyProtocol[CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_eof(client)

    # Verify close details
    assert_equal(Bool(client.get_close_rcvd()), False)
    assert_equal(Bool(client.get_close_sent()), False)
    assert_equal(Bool(client.get_close_rcvd_then_sent()), False)

    close_exc = get_close_exc(client)
    assert_equal(String(close_exc), "ConnectionClosedError: False, False, False")


fn test_close_exc_if_server_receives_eof() raises:
    """Test client-initiated close handshake on the server side times out."""
    server = DummyProtocol[SERVER](OPEN, StreamReader(), Bytes(), List[Event]())
    receive_eof(server)

    # Verify close details
    assert_equal(Bool(server.get_close_rcvd()), False)
    assert_equal(Bool(server.get_close_sent()), False)
    assert_equal(Bool(server.get_close_rcvd_then_sent()), False)

    close_exc = get_close_exc(server)
    assert_equal(String(close_exc), "ConnectionClosedError: False, False, False")
