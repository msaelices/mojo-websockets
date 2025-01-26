from collections import Optional

from websockets.aliases import Bytes, DEFAULT_MAX_REQUEST_BODY_SIZE
from websockets.http import HTTPRequest, HTTPResponse
from websockets.frames import (
       Close,
       Frame,
       CLOSE_CODE_ABNORMAL_CLOSURE,
       CLOSE_CODE_PROTOCOL_ERROR,
       CLOSE_CODE_NO_STATUS_RCVD,
       OK_CLOSE_CODES,
       OP_BINARY,
       OP_CLOSE,
       OP_CONT,
       OP_PING,
       OP_PONG,
       OP_TEXT,
)
from websockets.streams import StreamReader
from websockets.utils.bytes import gen_mask
from websockets.protocol import CONNECTING, Protocol, Event


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
    """
    # See https://github.com/python-websockets/websockets/blob/59d4dcf779fe7d2b0302083b072d8b03adce2f61/src/websockets/protocol.py#L254
    if protocol.get_discard_sent() and not protocol.get_reader_ptr()[].at_eof():
        return None

    _ = parse[gen_mask_func=gen_mask_func](protocol, data)



fn parse[
    T: Protocol,
    gen_mask_func: fn () -> Bytes = gen_mask,
](mut protocol: T, data: Optional[Bytes] = None) raises -> Event:
    """Parse a frame from a bytestring.

    Args:
        protocol: Protocol instance.
        data: Data to parse.

    Parameters:
        T: Protocol.
        gen_mask_func: Function to generate a mask.

    Returns:
        Event: Either an HTTPRequest during connection handshake or a Frame during normal operation.

    Raises:
        Error: If parsing fails.
    """
    if data:
        reader_ptr = protocol.get_reader_ptr()
        reader_ptr[].feed_data(data.value())

    # See https://github.com/python-websockets/websockets/blob/59d4dcf779fe7d2b0302083b072d8b03adce2f61/src/websockets/server.py#L549
    if protocol.get_state() == CONNECTING:
        optional_request = parse_handshake(protocol)
        if not optional_request:
            # TODO: change to just return None when the Mojo compiler does not complain
            return NoneType()
        return optional_request.value()
    else:
        optional_frame = parse_frame[gen_mask_func=gen_mask_func](protocol)
        if not optional_frame:
            # TODO: change to just return None when the Mojo compiler does not complain
            return NoneType()
        return optional_frame.value()


fn parse_handshake[T: Protocol](mut protocol: T) raises -> Optional[HTTPRequest]:
    """
    Parse an HTTP request.

    Args:
        protocol: Protocol instance.

    Parameters:
        T: Protocol.

    Returns:
        HTTPRequest: The parsed HTTP request.

    Raises:
        Error: If parsing fails.
    """
    reader_ptr = protocol.get_reader_ptr()

    @parameter
    if T.side == SERVER:
        try:
            request, bytes_read = HTTPRequest.from_bytes(
                'http://localhost',   # TODO: Use actual host
                DEFAULT_MAX_REQUEST_BODY_SIZE,
                reader_ptr[].buffer,
            )
            # Advance the reader by the number of bytes read plus 2 for the CRLF
            reader_ptr[].advance(bytes_read + 2)
            protocol.add_event(request)
            return request
        except exc:
            protocol.set_handshake_exc(exc)
    else:  # Client logic for parsing handshake HTTP response
        try:
            response = HTTPResponse.from_bytes(
                reader_ptr[].buffer,
            )
            protocol.add_event(response)
            protocol.process_response(response)
        except exc:
            protocol.set_handshake_exc(exc)
            send_eof(protocol)
            discard(protocol)
    return None


fn parse_frame[
    T: Protocol,
    gen_mask_func: fn () -> Bytes = gen_mask,
](mut protocol: T) raises -> Optional[Frame]:
    """
    Parse incoming data into frames.

    Args:
        protocol: Protocol instance.

    Parameters:
        T: Protocol.
        gen_mask_func: Function to generate a mask.

    Returns:
        Frame: The parsed WebSocket frame.

    Raises:
        Error: If parsing fails.
    """
    return parse_buffer[gen_mask_func=gen_mask_func](protocol)


fn parse_buffer[
    T: Protocol,
    gen_mask_func: fn () -> Bytes = gen_mask,
](mut protocol: T) raises -> Optional[Frame]:
    """
    Parse the buffer into a frame.

    Parameters:
        T: Protocol.
        gen_mask_func: Function to generate a mask.

    Args:
        protocol: Protocol instance.

    Returns:
        Frame: The parsed WebSocket frame.
    """
    var reader_ptr = protocol.get_reader_ptr()
    var err: Optional[Error] = None
    var optional_frame: Optional[Frame] = None
    try:
        optional_frame = Frame.parse(
            reader_ptr, mask=protocol.is_masked(),
        )
        if optional_frame:
            receive_frame[gen_mask_func=gen_mask_func](protocol, optional_frame.value())
            protocol.add_event(optional_frame.value())
        err = None
        return optional_frame
    except error:
        err = error
        # TODO: Differentiate between protocol errors, connection and other kind of errors
        code = CLOSE_CODE_PROTOCOL_ERROR
        reason = String(error)
        event = Frame(OP_CLOSE, Close(code, reason).serialize(), fin=True)

        # Fail the WebSocket Connection
        fail[gen_mask_func=gen_mask_func](protocol, code, reason)
        protocol.add_event(event)

    protocol.set_parser_exc(err)

    return None


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

        # Parse for any remaining data in the buffer.
        _ = parse_buffer(protocol)
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
    if protocol.get_state() == CLOSED:
        raise Error("InvalidState: connection is closed")
    if protocol.get_eof_sent():
        raise Error("ProtocolError: EOF already sent")

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
    # TODO: Find out why the following code is failing in some tests in test_protocol.mojo
    # if (protocol.get_state() == CONNECTING or T.side == SERVER) != (protocol.get_eof_sent()):
    #     raise Error("ProtocolError: EOF not sent when it should or sent when it shouldn't")

    reader_ptr = protocol.get_reader_ptr()
    reader_ptr[].discard()
    # The following code is commented as reader is not a generator (not supported in Mojo)
    # TODO: Implement the equivalent of the following Python code:
    # while not reader.at_eof():
    #     reader.discard()
    protocol.set_discard_sent(True)

    # A server closes the TCP connection immediately, while a client
    # waits for the server to close the TCP connection.
    if reader_ptr[].at_eof():
        protocol.set_state(CLOSED)

        @parameter
        if T.side == CLIENT:
            if protocol.get_state() != CONNECTING:
                send_eof(protocol)

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


fn fail[
    T: Protocol,
    gen_mask_func: fn () -> Bytes = gen_mask
](mut protocol: T, code: Int, reason: String = '') raises -> None:
    """
    `Fail the WebSocket connection`_.

    .. _Fail the WebSocket connection:
        https://datatracker.ietf.org/doc/html/rfc6455#section-7.1.7

    Parameters:
        T: Protocol.
        gen_mask_func: Function to generate a mask.

    Args:
        protocol: Protocol instance.
        code: Close code.
        reason: Close reason.

    Raises:
        ProtocolError: If the code isn't valid.
    """
    # 7.1.7. Fail the WebSocket Connection

    # Send a close frame when the state is OPEN (a close frame was already
    # sent if it's CLOSING), except when failing the connection because
    # of an error reading from or writing to the network.
    if protocol.get_state() == OPEN:
        if code != CLOSE_CODE_ABNORMAL_CLOSURE:
            close = Close(code, reason)
            data = close.serialize()
            send_frame[gen_mask_func=gen_mask_func](protocol, Frame(OP_CLOSE, data))
            protocol.set_close_sent(close)
            # If recv_messages() raised an exception upon receiving a close
            # frame but before echoing it, then close_rcvd is not None even
            # though the state is OPEN. This happens when the connection is
            # closed while receiving a fragmented message.
            if protocol.get_close_rcvd():
                protocol.set_close_rcvd_then_sent(True)
            protocol.set_state(CLOSING)

    # When failing the connection, a server closes the TCP connection
    # without waiting for the client to complete the handshake, while a
    # client waits for the server to close the TCP connection, possibly
    # after sending a close frame that the client will ignore.
    if T.side == SERVER and not protocol.get_eof_sent():
        send_eof(protocol)

    # 7.1.7. Fail the WebSocket Connection "An endpoint MUST NOT continue
    # to attempt to process data(including a responding Close frame) from
    # the remote endpoint after being instructed to _Fail the WebSocket
    # Connection_."
    discard(protocol)


fn receive_eof[T: Protocol](mut protocol: T) raises:
    """
    Receive the end of the data stream from the network.

    After calling this method:

    - You must call `data_to_send` and send this data to the network;
      it will return `[b""]`, signaling the end of the stream, or `[]`.
    - You aren't expected to call `events_received`; it won't return
      any new events.

    `receive_eof` is idempotent.
    """
    if protocol.get_state() == OPEN:
        protocol.set_parser_exc(Error("EOFError: unexpected end of stream"))
    elif protocol.get_state() == CONNECTING:
        protocol.set_handshake_exc(Error("EOFError: connection closed before handshake completed"))
        return

    if protocol.get_eof_sent() and protocol.get_state() == CLOSED:
        return

    try:
        protocol.get_reader_ptr()[].feed_eof()
    except error:
        protocol.set_parser_exc(error)
    protocol.set_state(CLOSED)

    _ = parse(protocol)


fn send_ping[
    T: Protocol,
    gen_mask_func: fn () -> Bytes = gen_mask,
](mut protocol: T, data: Bytes) raises -> None:
    """
    Send a `Ping frame`_.

    .. _Ping frame:
        https://datatracker.ietf.org/doc/html/rfc6455#section-5.5.2

    Parameters:
        T: Protocol.
        gen_mask_func: Function to generate a mask.

    Args:
        protocol: Protocol instance.
        data: Payload containing arbitrary binary data.

    Raises:
        InvalidState: If the connection is not open or closing.
    """
    # RFC 6455 allows control frames after starting the closing handshake.
    state = protocol.get_state()
    if state != OPEN and state != CLOSING:
        raise Error("InvalidState: connection is {}".format(state))
    send_frame[gen_mask_func=gen_mask_func](protocol, Frame(OP_PING, data))


fn close_expected[T: Protocol](protocol: T) -> Bool:
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
    return protocol.get_state() == CLOSING or protocol.get_handshake_exc()


fn get_close_exc[T: Protocol](protocol: T) raises -> Error:
    """
    Exception to raise when trying to interact with a closed connection.

    Don't raise this exception while the connection :attr:`state`
    is `~websockets.protocol.State.CLOSING`; wait until
    it's `~websockets.protocol.State.CLOSED`.

    Indeed, the exception includes the close code and reason, which are
    known only once the connection is closed.

    Parameters:
        T: Protocol.

    Args:
        protocol: Protocol instance.

    Returns:
        Error: Exception to raise when trying to interact with a closed connection.
    """
    if protocol.get_state() != CLOSED:
        raise Error("connection isn't closed yet")
    close_rcvd = protocol.get_close_rcvd()
    close_sent = protocol.get_close_sent()
    close_rcvd_then_sent = protocol.get_close_rcvd_then_sent()
    if (
        close_rcvd
        and close_sent
        and Int(close_rcvd.value().code) in OK_CLOSE_CODES
        and Int(close_sent.value().code) in OK_CLOSE_CODES
    ):
        return Error("ConnectionClosedOK: {}, {}".format(close_rcvd.value().code, close_sent.value().code))
    else:
        return Error("ConnectionClosedError: {}, {}, {}".format(Bool(close_rcvd), Bool(close_sent), Bool(close_rcvd_then_sent)))
