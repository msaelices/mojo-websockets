from collections import Dict
from time import perf_counter_ns as now

from libc import Bytes

from .aliases import Duration
from .utils.string import (
    ByteReader,
    ByteWriter,
    BytesConstant,
    bytes,
    is_newline,
    is_space,
    lineBreak, 
    nChar,
    rChar,
    HTTP11,
    SLASH,
    to_string, 
    whitespace,
)
from .utils.uri import URI
from .net import TCPAddr

struct HeaderKey:
    alias CONNECTION = "connection"
    alias CONTENT_TYPE = "content-type"
    alias CONTENT_LENGTH = "content-length"
    alias CONTENT_ENCODING = "content-encoding"
    alias DATE = "date"


@value
struct Header:
    var key: String
    var value: String


@always_inline
fn write_header[W: Writer](mut writer: W, key: String, value: String):
    writer.write(key + ": ", value, lineBreak)


@always_inline
fn write_header(mut writer: ByteWriter, key: String, inout value: String):
    var k = key + ": "
    writer.write(k)
    writer.write(value)
    writer.write(lineBreak)


@always_inline
fn encode(owned req: HTTPRequest) -> Bytes:
    return req._encoded()


@always_inline
fn encode(owned res: HTTPResponse) -> Bytes:
    return res._encoded()


@value
struct Headers(Writable, Stringable):
    """Represents the header key/values in an http request/response.

    Header keys are normalized to lowercase
    """

    var _inner: Dict[String, String]

    fn __init__(out self):
        self._inner = Dict[String, String]()

    fn __init__(out self, owned *headers: Header):
        self._inner = Dict[String, String]()
        for header in headers:
            self[header[].key.lower()] = header[].value

    @always_inline
    fn empty(self) -> Bool:
        return len(self._inner) == 0

    @always_inline
    fn __contains__(self, key: String) -> Bool:
        return key.lower() in self._inner

    @always_inline
    fn __getitem__(self, key: String) -> String:
        try:
            return self._inner[key.lower()]
        except:
            return String()

    @always_inline
    fn __setitem__(inout self, key: String, value: String):
        self._inner[key.lower()] = value

    fn content_length(self) -> Int:
        if HeaderKey.CONTENT_LENGTH not in self:
            return 0
        try:
            return int(self[HeaderKey.CONTENT_LENGTH])
        except:
            return 0

    fn parse_raw(
        inout self, inout r: ByteReader
    ) raises -> (String, String, String):
        var first_byte = r.peek()
        if not first_byte:
            raise Error("Failed to read first byte from response header")

        var first = r.read_word()
        r.increment()
        var second = r.read_word()
        r.increment()
        var third = r.read_line()

        while not is_newline(r.peek()):
            var key = r.read_until(BytesConstant.colon)
            r.increment()
            if is_space(r.peek()):
                r.increment()
            # TODO (bgreni): Handle possible trailing whitespace
            var value = r.read_line()
            self._inner[to_string(key^).lower()] = to_string(value^)
        return (to_string(first^), to_string(second^), to_string(third^))

    fn write_to[W: Writer](self, mut writer: W):
        for header in self._inner.items():
            write_header(writer, header[].key, header[].value)

    fn encode_to(inout self, mut writer: ByteWriter):
        for header in self._inner.items():
            write_header(writer, header[].key, header[].value)

    fn __str__(self) -> String:
        var output = String()
        self.write_to(output)
        return output


@value
struct HTTPRequest(Writable, Stringable):
    var headers: Headers
    var path: String
    var body_raw: Bytes

    var method: String
    var protocol: String

    var server_is_tls: Bool
    var timeout: Duration

    @staticmethod
    fn from_bytes(
        addr: String, max_body_size: Int, owned b: Bytes
    ) raises -> HTTPRequest:
        var reader = ByteReader(b^)
        var headers = Headers()
        var method: String
        var protocol: String
        var uri_str: String
        try:
            method, uri_str, protocol = headers.parse_raw(reader)
        except e:
            raise Error("Failed to parse request headers: " + e.__str__())

        var uri = URI.parse_raises(addr + uri_str)

        var content_length = headers.content_length()

        if (
            content_length > 0
            and max_body_size > 0
            and content_length > max_body_size
        ):
            raise Error("Request body too large")

        var request = HTTPRequest(
            uri.path, headers=headers, method=method, protocol=protocol
        )

        try:
            request.read_body(reader, content_length, max_body_size)
        except e:
            raise Error("Failed to read request body: " + e.__str__())

        return request

    fn __init__(
        out self,
        path: String,
        headers: Headers = Headers(),
        method: String = "GET",
        protocol: String = HTTP11,
        body: Bytes = Bytes(),
        server_is_tls: Bool = False,
        timeout: Duration = Duration(),
    ):
        self.headers = headers
        self.method = method
        self.protocol = protocol
        self.path = path
        self.body_raw = body
        self.server_is_tls = server_is_tls
        self.timeout = timeout
        self.set_content_length(len(body))
        if HeaderKey.CONNECTION not in self.headers:
            self.set_connection_close()

    fn set_connection_close(inout self):
        self.headers[HeaderKey.CONNECTION] = "close"

    fn set_content_length(inout self, l: Int):
        self.headers[HeaderKey.CONTENT_LENGTH] = str(l)

    fn connection_close(self) -> Bool:
        return self.headers[HeaderKey.CONNECTION] == "close"

    @always_inline
    fn read_body(
        inout self, inout r: ByteReader, content_length: Int, max_body_size: Int
    ) raises -> None:
        if content_length > max_body_size:
            raise Error("Request body too large")

        r.consume(self.body_raw)
        self.set_content_length(content_length)

    fn write_to[W: Writer](self, mut writer: W):
        writer.write(
            self.method,
            whitespace,
            self.path if len(self.path) > 1 else SLASH,
            whitespace,
            self.protocol,
            lineBreak,
        )

        self.headers.write_to(writer)
        writer.write(lineBreak)
        writer.write(to_string(self.body_raw))

    fn _encoded(inout self) -> Bytes:
        """Encodes request as bytes.

        This method consumes the data in this request and it should
        no longer be considered valid.
        """
        var writer = ByteWriter()
        writer.write(self.method)
        writer.write(whitespace)
        var path = self.path if len(self.path) > 1 else SLASH
        writer.write(path)
        writer.write(whitespace)
        writer.write(self.protocol)
        writer.write(lineBreak)

        self.headers.encode_to(writer)
        writer.write(lineBreak)

        writer.write(self.body_raw)

        return writer.consume()

    fn __str__(self) -> String:
        var output = String()
        self.write_to(output)
        return output


@value
struct HTTPResponse(Writable, Stringable):
    var headers: Headers
    var body_raw: Bytes
    var skip_reading_writing_body: Bool
    var raddr: TCPAddr
    var laddr: TCPAddr
    var __is_upgrade: Bool

    var status_code: Int
    var status_text: String
    var protocol: String

    @staticmethod
    fn from_bytes(owned b: Bytes) raises -> HTTPResponse:
        var reader = ByteReader(b^)

        var headers = Headers()
        var protocol: String
        var status_code: String
        var status_text: String

        try:
            protocol, status_code, status_text = headers.parse_raw(reader)
        except e:
            raise Error("Failed to parse response headers: " + e.__str__())

        var response = HTTPResponse(
            Bytes(),
            headers=headers,
            protocol=protocol,
            status_code=int(status_code),
            status_text=status_text,
        )

        try:
            response.read_body(reader)
            return response
        except e:
            raise Error("Failed to read request body: " + e.__str__())

    fn __init__(
        out self,
        body_bytes: Bytes,
        headers: Headers = Headers(),
        status_code: Int = 200,
        status_text: String = "OK",
        protocol: String = HTTP11,
    ):
        self.headers = headers
        if HeaderKey.CONTENT_TYPE not in self.headers:
            self.headers[HeaderKey.CONTENT_TYPE] = "application/octet-stream"
        self.status_code = status_code
        self.status_text = status_text
        self.protocol = protocol
        self.body_raw = body_bytes
        self.skip_reading_writing_body = False
        self.__is_upgrade = False
        self.raddr = TCPAddr()
        self.laddr = TCPAddr()
        self.set_connection_keep_alive()
        self.set_content_length(len(body_bytes))

    fn get_body_bytes(self) -> Bytes:
        return self.body_raw

    @always_inline
    fn set_connection_close(inout self):
        self.headers[HeaderKey.CONNECTION] = "close"

    @always_inline
    fn set_connection_keep_alive(inout self):
        self.headers[HeaderKey.CONNECTION] = "keep-alive"

    fn connection_close(self) -> Bool:
        return self.headers[HeaderKey.CONNECTION] == "close"

    @always_inline
    fn set_content_length(inout self, l: Int):
        self.headers[HeaderKey.CONTENT_LENGTH] = str(l)

    @always_inline
    fn read_body(inout self, inout r: ByteReader) raises -> None:
        r.consume(self.body_raw)

    fn write_to[W: Writer](self, mut writer: W):
        writer.write(
            self.protocol,
            whitespace,
            self.status_code,
            whitespace,
            self.status_text,
            lineBreak,
            "server: websockets",
            lineBreak,
        )

        if HeaderKey.DATE not in self.headers:
            # TODO: Use UTC time
            var current_time = now().__str__()
            write_header(writer, HeaderKey.DATE, current_time)

        self.headers.write_to(writer)

        writer.write(lineBreak)
        writer.write(to_string(self.body_raw))

    fn _encoded(inout self) -> Bytes:
        """Encodes response as bytes.

        This method consumes the data in this request and it should
        no longer be considered valid.
        """
        var writer = ByteWriter()
        writer.write(self.protocol)
        writer.write(whitespace)
        writer.write(bytes(str(self.status_code)))
        writer.write(whitespace)
        writer.write(self.status_text)
        writer.write(lineBreak)
        writer.write("server: websockets")
        writer.write(lineBreak)

        if HeaderKey.DATE not in self.headers:
            # TODO: Use UTC time
            var current_time = now().__str__()
            write_header(writer, HeaderKey.DATE, current_time)

        self.headers.encode_to(writer)

        writer.write(lineBreak)
        writer.write(self.body_raw)

        return writer.consume()

    fn __str__(self) -> String:
        output = String()
        self.write_to(output)
        return output

