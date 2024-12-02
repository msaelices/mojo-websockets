from websockets.aliases import Bytes, DEFAULT_MAX_REQUEST_BODY_SIZE
from websockets.http import HTTPRequest
from websockets.frames import Frame
from websockets.streams import StreamReader

from . import CONNECTING, Protocol, Event, parse


struct ServerProtocol(Protocol):
    """
    Sans-I/O implementation of a WebSocket server connection.
    """
    var reader: StreamReader
    var events: List[Event]
    var state: Int

    fn __init__(inout self) -> None:
        self.reader = StreamReader()
        self.events = List[Event]()
        self.state = CONNECTING

    fn receive_data(inout self, data: Bytes) raises:
        """Feed data and receive frames."""
        self.reader.feed_data(data)
        self.parse(data)

    fn parse(inout self, data: Bytes) raises:
        """Parse a frame from a bytestring."""
        if self.state == CONNECTING:
            response = HTTPRequest.from_bytes(
                'http://localhost',   # TODO: Use actual host
                DEFAULT_MAX_REQUEST_BODY_SIZE,
                data, 
            )
            self.events.append(response)
        else:
            frame = parse(self.reader, data, mask=True)
            self.events.append(frame)

    # from ServerProtocol.parse() in websockets/protocol/server.py
    # if self.state is CONNECTING:
    #     try:
    #         request = yield from Request.parse(
    #             self.reader.read_line,
    #         )
    #     except Exception as exc:
    #         self.handshake_exc = exc
    #         self.send_eof()
    #         self.parser = self.discard()
    #         next(self.parser)  # start coroutine
    #         yield
    #
    #     if self.debug:
    #         self.logger.debug("< GET %s HTTP/1.1", request.path)
    #         for key, value in request.headers.raw_items():
    #             self.logger.debug("< %s: %s", key, value)
    #
    #     self.events.append(request)
    #
    # yield from super().parse()
