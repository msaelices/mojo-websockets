from utils import Variant

from websockets.aliases import Bytes
from websockets.frames import Frame
from websockets.http import HTTPRequest, HTTPResponse
from websockets.streams import StreamReader

alias CONNECTING = 0
alias OPEN = 1
alias CLOSING = 2
alias CLOSED = 3

alias Event = Variant[HTTPRequest, HTTPResponse, Frame]


trait Protocol:
    fn receive_data(inout self, data: Bytes) raises:
        """Feed data and receive frames."""
        pass


fn parse(inout reader: StreamReader, data: Bytes, mask: Bool) raises -> Frame:
    """
    Parse incoming data into frames.
    """
    reader.feed_data(data)
    reader.feed_eof()
    frame = Frame.parse(
        reader, mask=mask,
    )
    return frame
