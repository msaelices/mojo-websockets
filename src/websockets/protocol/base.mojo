from collections import Optional

from websockets.aliases import Bytes, DEFAULT_MAX_REQUEST_BODY_SIZE
from websockets.http import HTTPRequest
from websockets.frames import (
       Close,
       Frame,
       CLOSE_CODE_PROTOCOL_ERROR,
       CLOSE_CODE_NO_STATUS_RCVD,
       OP_BINARY,
       OP_CLOSE,
       OP_CONT,
       OP_PING,
       OP_PONG,
       OP_TEXT,
)
from websockets.streams import StreamReader
from websockets.utils.bytes import gen_mask
from . import CONNECTING, Protocol, Event


fn receive_data[
    T: Protocol,
    gen_mask_func: fn () -> Bytes = gen_mask,
](mut protocol: T, data: Bytes) raises:
    """Feed data and receive frames.
    Args:
        protocol: Protocol instance.
        data: Data to feed.

    Parameters:
        T: Protocol.
        gen_mask_func: Function to generate a mask.

    Returns:
        Tuple containing the parsed event and any error that occurred.
    """
    # See https://github.com/python-websockets/websockets/blob/59d4dcf779fe7d2b0302083b072d8b03adce2f61/src/websockets/protocol.py#L254
    reader = protocol.get_reader()
    reader.feed_data(data)
    if protocol.get_discard_sent():
        return None

    var err: Optional[Error] = None
    try:
        event = parse(protocol, data)
        if event.isa[Frame]():
            receive_frame[gen_mask_func=gen_mask_func](protocol, event[Frame])
        err = None
    except error:
        err = error
        # TODO: Differentiate between protocol errors, connection and other kind of errors
        event = Frame(OP_CLOSE, Close(CLOSE_CODE_PROTOCOL_ERROR, str(error._message())).serialize(), fin=True)  # Close the connection on error

    protocol.add_event(event)
    protocol.set_parser_exc(err)


fn parse[T: Protocol](mut protocol: T, data: Bytes) raises -> Event:
    """Parse a frame from a bytestring.

    Args:
        protocol: Protocol instance.
        data: Data to parse.

    Parameters:
        T: Protocol.

    Returns:
        Event: Either an HTTPRequest during connection handshake or a Frame during normal operation.

    Raises:
        Error: If parsing fails.
    """
    # See https://github.com/python-websockets/websockets/blob/59d4dcf779fe7d2b0302083b072d8b03adce2f61/src/websockets/server.py#L549
    if protocol.get_state() == CONNECTING:
        response = HTTPRequest.from_bytes(
            'http://localhost',   # TODO: Use actual host
            DEFAULT_MAX_REQUEST_BODY_SIZE,
            data, 
        )
        return response
    else:
        return parse_frame(protocol, data)


fn parse_frame[T: Protocol](mut protocol: T, data: Bytes) raises -> Frame:
    """
    Parse incoming data into frames.

    Args:
        protocol: Protocol instance.
        data: Data to parse into frames.

    Parameters:
        T: Protocol.

    Returns:
        Frame: The parsed WebSocket frame.

    Raises:
        Error: If parsing fails.
    """
    reader = protocol.get_reader()
    reader.feed_data(data)
    reader.feed_eof()
    frame = Frame.parse(
        reader, mask=protocol.is_masked(),
    )
    return frame


fn receive_frame[
    T: Protocol,
    gen_mask_func: fn () -> Bytes = gen_mask,
](mut protocol: T, frame: Frame) raises -> None:
    """
    Process an incoming frame.

    Args:
        protocol: Protocol instance.
        frame: Frame to process.

    Parameters:
        T: Protocol.
        gen_mask_func: Function to generate a mask.

    Raises:
        Error: If the frame is invalid.
    """
    if frame.opcode == OP_TEXT or frame.opcode == OP_BINARY:
        if protocol.get_curr_size():
            raise Error("ProtocolError: expected a continuation frame")
        if frame.fin:
            protocol.set_curr_size(None)
        else:
            protocol.set_curr_size(len(frame.data))

    elif frame.opcode == OP_CONT:
        if not protocol.get_curr_size():
            raise Error("ProtocolError: unexpected continuation frame")
        if frame.fin:
            protocol.set_curr_size(None)
        else:
            protocol.set_curr_size(protocol.get_curr_size().value() + len(frame.data))

    elif frame.opcode == OP_PING:
        # 5.5.2. Ping: "Upon receipt of a Ping frame, an endpoint MUST
        # send a Pong frame in response"
        pong_frame = Frame(OP_PONG, frame.data)
        send_frame[gen_mask_func=gen_mask_func](protocol, pong_frame)

    elif frame.opcode == OP_PONG:
        # 5.5.3 Pong: "A response to an unsolicited Pong frame is not
        # expected."
        pass

    elif frame.opcode == OP_CLOSE:
        # 7.1.5.  The WebSocket Connection Close Code
        # 7.1.6.  The WebSocket Connection Close Reason
        protocol.set_close_rcvd(Close.parse(frame.data))
        if protocol.get_state() == CLOSING:
            # assert protocol.close_sent is not None
            protocol.set_close_rcvd_then_sent(False)

        if protocol.get_curr_size():
            raise Error("ProtocolError: incomplete fragmented message")

        # 5.5.1 Close: "If an endpoint receives a Close frame and did
        # not previously send a Close frame, the endpoint MUST send a
        # Close frame in response. (When sending a Close frame in
        # response, the endpoint typically echos the status code it
        # received.)"

        if protocol.get_state() == OPEN:
            # Echo the original data instead of re-serializing it with
            # Close.serialize() because that fails when the close frame
            # is empty and Close.parse() synthesizes a 1005 close code.
            # The rest is identical to send_close().
            send_frame[gen_mask_func=gen_mask_func](protocol, Frame(OP_CLOSE, frame.data))
            protocol.set_close_sent(protocol.get_close_rcvd())
            protocol.set_close_rcvd_then_sent(True)
            protocol.set_state(CLOSING)

        # 7.1.2. Start the WebSocket Closing Handshake: "Once an
        # endpoint has both sent and received a Close control frame,
        # that endpoint SHOULD _Close the WebSocket Connection_"

        # A server closes the TCP connection immediately, while a client
        # waits for the server to close the TCP connection.
        @parameter
        if T.side == SERVER:
            send_eof(protocol)

        # 1.4. Closing Handshake: "after receiving a control frame
        # indicating the connection should be closed, a peer discards
        # any further data received."
        # RFC 6455 allows reading Ping and Pong frames after a Close frame.
        # However, that doesn't seem useful; websockets doesn't support it.
        discard(protocol)

    else:
        # This can't happen because Frame.parse() validates opcodes.
        raise Error("AssertionError: unexpected opcode: {}".format(frame.opcode))


fn send_text[
    T: Protocol,
    gen_mask_func: fn () -> Bytes = gen_mask,
](mut protocol: T, data: Bytes, fin: Bool = True) raises -> None:
    """
    Send a `Text frame`_.

    .. _Text frame:
        https://datatracker.ietf.org/doc/html/rfc6455#section-5.6

    Parameters:
        T: Protocol.
        gen_mask_func: Function to generate a mask.

    Args:
        protocol: Protocol instance.
        data: Payload containing text encoded with UTF-8.
        fin: FIN bit; set it to :obj:`False` if this is the first frame of
            a fragmented message.

    Raises:
        ProtocolError: If a fragmented message is in progress.

    """
    state = protocol.get_state()
    if protocol.expect_continuation_frame():
        raise Error("ProtocolError: expected a continuation frame")
    if state != OPEN:
        raise Error("InvalidState: connection is {}".format(state))

    protocol.set_expect_continuation_frame(not fin)
    send_frame[gen_mask_func=gen_mask_func](protocol, Frame(OP_TEXT, data, fin))


fn send_frame[
    T: Protocol,
    gen_mask_func: fn () -> Bytes = gen_mask,
](mut protocol: T, frame: Frame) raises -> None:
    """
    Send a frame.

    Parameters:
        T: Protocol.
        gen_mask_func: Function to generate a mask.

    Args:
        protocol: Protocol instance.
        frame: Frame to send.

    Raises:
        ProtocolError: If a fragmented message is in progress.
    """
    protocol.write_data(
        frame.serialize[gen_mask_func=gen_mask_func](
            mask=protocol.is_masked(),
        )
    )


fn send_continuation[
    T: Protocol,
    gen_mask_func: fn () -> Bytes = gen_mask,
](mut protocol: T, data: Bytes, fin: Bool) raises -> None:
    """
    Send a `Continuation frame`_.

    .. _Continuation frame:
        https://datatracker.ietf.org/doc/html/rfc6455#section-5.6

    Parameters:
        T: Protocol.
        gen_mask_func: Function to generate a mask.

    Args:
        protocol: Protocol instance.
        data: Payload containing the same kind of data
            as the initial frame.
        fin: FIN bit; set it to :obj:`True` if this is the last frame
            of a fragmented message and to :obj:`False` otherwise.
    
    Raises:
        ProtocolError: If an unexpected continuation frame is received.
        InvalidState: If the connection is not open.
    """
    if not protocol.expect_continuation_frame():
        raise Error("ProtocolError: unexpected continuation frame")
    if protocol.get_state() != OPEN:
        raise Error("InvalidState: connection is not open")
    protocol.set_expect_continuation_frame(not fin)
    send_frame[gen_mask_func=gen_mask_func](protocol, Frame(OP_CONT, data, fin))


fn send_eof[T: Protocol](mut protocol: T) raises -> None:
    """
    Send an EOF frame.

    Args:
        protocol: Protocol instance.

    Parameters:
        T: Protocol.

    Raises:
        ProtocolError: If EOF was already sent.
    """
    if protocol.get_eof_sent():
        raise Error("ProtocolError: EOF already sent")

    protocol.set_eof_sent(True)
    protocol.write_data(SEND_EOF)


fn discard[T: Protocol](mut protocol: T) raises:
    """
    Discard incoming data.

    This coroutine replaces `parse`:

    - after receiving a close frame, during a normal closure (1.4);
    - after sending a close frame, during an abnormal closure (7.1.7).

    Args:
        protocol: Protocol instance.
    """
    # After the opening handshake completes, the server closes the TCP
    # connection in the same circumstances where discard() replaces parse().
    # The client closes it when it receives EOF from the server or times
    # out. (The latter case cannot be handled in this Sans-I/O layer.)
    if (protocol.get_state() == CONNECTING or T.side == SERVER) != (protocol.get_eof_sent()):
        raise Error("ProtocolError: EOF not sent when it should or sent when it shouldn't")

    reader = protocol.get_reader()
    reader.discard()
    # The following code is commented as reader is not a generator (not supported in Mojo)
    # TODO: Implement the equivalent of the following Python code:
    # while not reader.at_eof():
    #     reader.discard()
    protocol.set_discard_sent(True)

    # A server closes the TCP connection immediately, while a client
    # waits for the server to close the TCP connection.
    @parameter
    if T.side == CLIENT:
        if protocol.get_state() != CONNECTING:
            send_eof(protocol)
    protocol.set_state(CLOSED)

    # TODO: Implement the equivalent of the following Python code:
    # # If discard() completes normally, execution ends here.
    # yield
    # # Once the reader reaches EOF, its feed_data/eof() methods raise an
    # # error, so our receive_data/eof() methods don't step the generator.
    # raise AssertionError("discard() shouldn't step after EOF")


fn send_close[
    T: Protocol,
    gen_mask_func: fn () -> Bytes = gen_mask,
](mut protocol: T, code: Optional[Int] = None, reason: String = "") raises -> None:
    """
    Send a `Close frame`_.

    .. _Close frame:
        https://datatracker.ietf.org/doc/html/rfc6455#section-5.5.1

    Args:
        protocol: Protocol instance.
        code: Close code.
        reason: Close reason.

    Parameters:
        T: Protocol.
        gen_mask_func: Function to generate a mask.

    Raises:
        ProtocolError: If the code isn't valid or if a reason is provided
            without a code.
    """
    # While RFC 6455 doesn't rule out sending more than one close Frame,
    # websockets is conservative in what it sends and doesn't allow that.
    if protocol.get_state() != OPEN:
        raise Error("InvalidState: connection is not open but {}".format(protocol.get_state()))
    if not code:
        if reason != "":
            raise Error("ProtocolError: cannot send a reason without a code")
        close = Close(CLOSE_CODE_NO_STATUS_RCVD, "")
        data = Bytes()
    else:
        close = Close(code.value(), reason)
        data = close.serialize()
    # 7.1.3. The WebSocket Closing Handshake is Started
    send_frame[gen_mask_func=gen_mask_func](protocol, Frame(OP_CLOSE, data))
    # Since the state is OPEN, no close frame was received yet.
    # As a consequence, protocol.close_rcvd_then_sent remains None.
    if protocol.get_close_rcvd():
        raise Error("Close frame received before sending one")

    protocol.set_close_sent(close)
    protocol.set_state(CLOSING)


fn send_binary[
    T: Protocol,
    gen_mask_func: fn () -> Bytes = gen_mask,
](mut protocol: T, data: Bytes, fin: Bool = True) raises -> None:
    """
    Send a `Binary frame`_.

    .. _Binary frame:
        https://datatracker.ietf.org/doc/html/rfc6455#section-5.6

    Parameters:
        T: Protocol.
        gen_mask_func: Function to generate a mask.

    Args:
        protocol: Protocol instance.
        data: Payload containing arbitrary binary data.
        fin: FIN bit; set it to :obj:`False` if this is the first frame of
            a fragmented message.

    Raises:
        ProtocolError: If a fragmented message is in progress.
    """
    if protocol.expect_continuation_frame():
        raise Error("ProtocolError: expected a continuation frame")
    if protocol.get_state() != OPEN:
        raise Error("InvalidState: connection is {}".format(protocol.get_state()))
    protocol.set_expect_continuation_frame(not fin)
    send_frame[gen_mask_func=gen_mask_func](protocol, Frame(OP_BINARY, data, fin))

