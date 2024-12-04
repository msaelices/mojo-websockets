from websockets.aliases import Bytes, DEFAULT_MAX_REQUEST_BODY_SIZE
from websockets.http import HTTPRequest
from websockets.frames import Frame
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
