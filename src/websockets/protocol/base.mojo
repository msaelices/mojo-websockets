from collections import Optional

from websockets.aliases import Bytes, DEFAULT_MAX_REQUEST_BODY_SIZE
from websockets.http import HTTPRequest
from websockets.frames import (
       Close,
       Frame,
       CLOSE_CODE_PROTOCOL_ERROR,
       OP_CLOSE,
       OP_CONT,
       OP_TEXT,
)
from websockets.streams import StreamReader
from websockets.utils.bytes import gen_mask
from . import CONNECTING, Protocol, Event


fn receive_data(inout reader: StreamReader, state: Int, data: Bytes, mask: Bool = False) raises -> Tuple[Event, Optional[Error]]:
    """Feed data and receive frames."""
    # See https://github.com/python-websockets/websockets/blob/59d4dcf779fe7d2b0302083b072d8b03adce2f61/src/websockets/protocol.py#L254
    reader.feed_data(data)
    var err: Optional[Error] = None
    try:
        event = parse(reader, state, data, mask)
        err = None
    except error:
        err = error
        # TODO: Differentiate between protocol errors, connection and other kind of errors
        event = Frame(OP_CLOSE, Close(CLOSE_CODE_PROTOCOL_ERROR, str(error._message())).serialize(), fin=True)  # Close the connection on error
    return event, err


fn parse(inout reader: StreamReader, state: Int, data: Bytes, mask: Bool = False) raises -> Event:
    """Parse a frame from a bytestring."""
    # See https://github.com/python-websockets/websockets/blob/59d4dcf779fe7d2b0302083b072d8b03adce2f61/src/websockets/server.py#L549
    if state == CONNECTING:
        response = HTTPRequest.from_bytes(
            'http://localhost',   # TODO: Use actual host
            DEFAULT_MAX_REQUEST_BODY_SIZE,
            data, 
        )
        return response
    else:
        return parse_frame(reader, data, mask=mask)


fn parse_frame(inout reader: StreamReader, data: Bytes, mask: Bool) raises -> Frame:
    """
    Parse incoming data into frames.
    """
    reader.feed_data(data)
    reader.feed_eof()
    frame = Frame.parse(
        reader, mask=mask,
    )
    return frame


fn send_text[
    T: Protocol,
    gen_mask_func: fn () -> Bytes = gen_mask,
](inout protocol: T, data: Bytes, fin: Bool = True) raises -> None:
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
](inout protocol: T, frame: Frame) raises -> None:
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
](inout protocol: T, data: Bytes, fin: Bool) raises -> None:
    """
    Send a `Continuation frame`_.

    .. _Continuation frame:
        https://datatracker.ietf.org/doc/html/rfc6455#section-5.6

    Parameters:
        T: Protocol.

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
    send_frame(protocol, Frame(OP_CONT, data, fin))
