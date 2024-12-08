from websockets.aliases import Bytes, DEFAULT_MAX_REQUEST_BODY_SIZE
from websockets.http import HTTPRequest
from websockets.frames import Frame, OP_TEXT
from websockets.streams import StreamReader
from . import CONNECTING, Protocol, Event


fn receive_data(inout reader: StreamReader, state: Int, data: Bytes) raises -> Event:
    """Feed data and receive frames."""
    # See https://github.com/python-websockets/websockets/blob/59d4dcf779fe7d2b0302083b072d8b03adce2f61/src/websockets/protocol.py#L254
    reader.feed_data(data)
    return parse(reader, state, data)


fn parse(inout reader: StreamReader, state: Int, data: Bytes) raises -> Event:
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
        # TODO: Mask depending on the side (server, client)
        return parse_frame(reader, data, mask=True)


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


fn send_text[T: Protocol](inout protocol: T, data: Bytes, fin: Bool = True) raises -> None:
    """
    Send a `Text frame`_.

    .. _Text frame:
        https://datatracker.ietf.org/doc/html/rfc6455#section-5.6

    Parameters:
        T: Protocol.

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
    send_frame(protocol, Frame(OP_TEXT, data, fin))


fn send_frame[T: Protocol](inout protocol: T, frame: Frame) raises -> None:
    """
    Send a frame.

    Parameters:
        T: Protocol.

    Args:
        protocol: Protocol instance.
        frame: Frame to send.

    Raises:
        ProtocolError: If a fragmented message is in progress.
    """
    protocol.write_data(
        frame.serialize(
            mask=protocol.is_masked(),
        )
    )
    
