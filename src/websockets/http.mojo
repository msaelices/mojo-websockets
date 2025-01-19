from base64 import b64encode
from collections import Dict, Optional
from memory import Span
from utils import StringSlice

from websockets.aliases import Bytes
from websockets.libc import AF_INET6

from websockets.aliases import Duration
from websockets.utils.string import (
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
from websockets.utils.time import now
from websockets.utils.uri import URI
from websockets.net import TCPAddr, get_address_info, addrinfo_macos, addrinfo_unix


struct HeaderKey:
    alias CONNECTION = "connection"
    alias CONTENT_TYPE = "content-type"
    alias CONTENT_LENGTH = "content-length"
    alias CONTENT_ENCODING = "content-encoding"
    alias DATE = "date"
    alias SET_COOKIE = "set-cookie"
    alias HOST = "host"
    alias COOKIE = "cookie"


@value
struct Header(Writable, Stringable):
    var key: String
    var value: String

    fn __str__(self) -> String:
        return String.write(self)

    fn write_to[T: Writer, //](self, mut writer: T):
        writer.write(self.key + ": ", self.value, lineBreak)


@always_inline
fn write_header[W: Writer](mut writer: W, key: String, value: String):
    writer.write(key + ": ", value, lineBreak)


@always_inline
fn write_header(mut writer: ByteWriter, key: String, mut value: String):
    var k = key + ": "
    writer.write(k)
    writer.write(value)
    writer.write(lineBreak)


@always_inline
fn encode(owned req: HTTPRequest) -> Bytes:
    return req.encode()


@always_inline
fn encode(owned res: HTTPResponse) -> Bytes:
    return res.encode()



fn get_date_timestamp() -> String:
    """
    Get the UTC String for the Date HTTP header.
    """
    # TODO: Return a UTC string valid in Date HTTP header, like "Thu, 02 Jan 2025 22:16:23 GMT"
    # See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Date
    try:
        return now(utc=True).__str__()
    except e:
        return e.__str__()


fn build_host_header(host: String, port: Int, secure: Bool) raises -> String:
    """
    Build a `Host` HTTP header.
    """
    # https://datatracker.ietf.org/doc/html/rfc3986#section-3.2.2
    # IPv6 addresses must be enclosed in brackets.
    try:
        address = get_address_info(host)
    except ValueError:
        # host is a hostname
        host_header = host
    else:
        host_header = host
        # host is an IP address
        if address.isa[addrinfo_macos]() and address[addrinfo_macos].ai_family == AF_INET6:
            host_header = "[{}]".format(host)
        elif address.isa[addrinfo_unix]() and address[addrinfo_unix].ai_family == AF_INET6:
            host_header = "[{}]".format(host)

    if port != (443 if secure else 80):
        host_header = "{}:{}".format(host_header, port)

    return host_header


fn build_authorization_basic(username: String, password: String) raises -> String:
    """
    Build an `Authorization` header for HTTP Basic Auth.
    """
    # https://datatracker.ietf.org/doc/html/rfc7617#section-2
    user_pass = "{}:{}".format(username, password)
    basic_credentials = b64encode(user_pass)
    return "Basic {}".format(basic_credentials)


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
    fn __getitem__(self, key: String) raises -> String:
        try:
            return self._inner[key.lower()]
        except:
            raise Error("KeyError: Key not found in headers: " + key)

    @always_inline
    fn get(self, key: String) -> Optional[String]:
        return self._inner.get(key.lower())

    @always_inline
    fn __setitem__(mut self, key: String, value: String):
        self._inner[key.lower()] = value

    fn content_length(self) -> Int:
        try:
            return Int(self[HeaderKey.CONTENT_LENGTH])
        except:
            return 0

    fn parse_raw(mut self, mut r: ByteReader) raises -> (String, String, String, List[String]):
        var first_byte = r.peek()
        if not first_byte:
            raise Error("Headers.parse_raw: Failed to read first byte from response header")

        var first = r.read_word()
        r.increment()
        var second = r.read_word()
        r.increment()
        var third = r.read_line()
        var cookies = List[String]()

        while not is_newline(r.peek()):
            var key = r.read_until(BytesConstant.colon)
            r.increment()
            if is_space(r.peek()):
                r.increment()
            # TODO (bgreni): Handle possible trailing whitespace
            var value = r.read_line()
            var k = to_string(key).lower()
            if k == HeaderKey.SET_COOKIE:
                cookies.append(to_string(value))
                continue

            self._inner[k] = to_string(value)
        return (to_string(first), to_string(second), to_string(third), cookies)

    fn write_to[T: Writer, //](self, mut writer: T):
        for header in self._inner.items():
            write_header(writer, header[].key, header[].value)

    fn __str__(self) -> String:
        return String.write(self)


@value
struct HTTPRequest(Writable, Stringable):
    var headers: Headers
    var uri: URI
    var body_raw: Bytes

    var method: String
    var protocol: String

    var timeout: Duration

    @staticmethod
    fn from_bytes(addr: String, max_body_size: Int, b: Span[Byte]) raises -> HTTPRequest:
        var reader = ByteReader(b)
        var headers = Headers()
        var method: String
        var protocol: String
        var uri: String
        try:
            var rest = headers.parse_raw(reader)
            method, uri, protocol = rest[0], rest[1], rest[2]
        except e:
            raise Error("HTTPRequest.from_bytes: Failed to parse request headers: " + String(e))

        var content_length = headers.content_length()
        if content_length > 0 and max_body_size > 0 and content_length > max_body_size:
            raise Error("HTTPRequest.from_bytes: Request body too large.")

        var request = HTTPRequest(
            URI.parse(addr + uri), headers=headers, method=method, protocol=protocol,
        )
        try:
            request.read_body(reader, content_length, max_body_size)
        except e:
            raise Error("HTTPRequest.from_bytes: Failed to read request body: " + String(e))

        return request

    fn __init__(
        out self,
        uri: URI,
        headers: Headers = Headers(),
        method: String = "GET",
        protocol: String = HTTP11,
        body: Bytes = Bytes(),
        timeout: Duration = Duration(),
    ):
        self.headers = headers
        self.method = method
        self.protocol = protocol
        self.uri = uri
        self.body_raw = body
        self.timeout = timeout
        self.set_content_length(len(body))
        if HeaderKey.CONNECTION not in self.headers:
            self.headers[HeaderKey.CONNECTION] = "keep-alive"
        if HeaderKey.HOST not in self.headers:
            self.headers[HeaderKey.HOST] = uri.host

    fn get_body(self) -> StringSlice[__origin_of(self.body_raw)]:
        return StringSlice(unsafe_from_utf8=Span(self.body_raw))

    fn set_connection_close(mut self):
        self.headers[HeaderKey.CONNECTION] = "close"

    fn set_content_length(mut self, l: Int):
        self.headers[HeaderKey.CONTENT_LENGTH] = String(l)

    fn connection_close(self) -> Bool:
        var result = self.headers.get(HeaderKey.CONNECTION)
        if not result:
            return False
        return result.value() == "close"

    @always_inline
    fn read_body(mut self, mut r: ByteReader, content_length: Int, max_body_size: Int) raises -> None:
        if content_length > max_body_size:
            raise Error("Request body too large")

        self.body_raw = Bytes(r.read_bytes(content_length))
        self.set_content_length(content_length)

    fn write_to[T: Writer, //](self, mut writer: T):
        path = self.uri.path if len(self.uri.path) > 1 else SLASH
        if len(self.uri.query_string) > 0:
            path.write("?", self.uri.query_string)

        writer.write(
            self.method,
            whitespace,
            path,
            whitespace,
            self.protocol,
            lineBreak,
            self.headers,
            lineBreak,
            to_string(self.body_raw),
        )

    fn encode(owned self) -> Bytes:
        """Encodes request as bytes.

        This method consumes the data in this request and it should
        no longer be considered valid.
        """
        var path = self.uri.path if len(self.uri.path) > 1 else SLASH
        if len(self.uri.query_string) > 0:
            path.write("?", self.uri.query_string)

        var writer = ByteWriter()
        writer.write(
            self.method,
            whitespace,
            path,
            whitespace,
            self.protocol,
            lineBreak,
            self.headers,
            lineBreak,
        )
        writer.consuming_write(self^.body_raw)
        return writer.consume()

    fn __str__(self) -> String:
        return String.write(self)


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
            status_code=Int(status_code),
            status_text=status_text,
            headers=headers,
            body_bytes=Bytes(),
            protocol=protocol,
        )

        try:
            response.read_body(reader)
            return response
        except e:
            raise Error("Failed to read request body: " + e.__str__())

    fn __init__(
        out self,
        status_code: Int,
        status_text: String,
        headers: Headers,
        body_bytes: Bytes,
        protocol: String = HTTP11,
    ):
        self.headers = headers
        self.status_code = status_code
        self.status_text = status_text
        self.protocol = protocol
        self.body_raw = body_bytes
        self.skip_reading_writing_body = False
        self.__is_upgrade = False
        self.raddr = TCPAddr()
        self.laddr = TCPAddr()

    fn get_body_bytes(self) -> Bytes:
        return self.body_raw

    fn get_body(self) -> StringSlice[__origin_of(self.body_raw)]:
        return StringSlice(unsafe_from_utf8=self.body_raw)

    @always_inline
    fn set_connection_close(mut self):
        self.headers[HeaderKey.CONNECTION] = "close"

    @always_inline
    fn set_connection_keep_alive(mut self):
        self.headers[HeaderKey.CONNECTION] = "keep-alive"

    fn connection_close(self) -> Bool:
        return self.headers[HeaderKey.CONNECTION] == "close"

    @always_inline
    fn set_content_length(mut self, l: Int):
        self.headers[HeaderKey.CONTENT_LENGTH] = String(l)

    @always_inline
    fn read_body(mut self, mut r: ByteReader) raises -> None:
        r.consume(self.body_raw)

    fn write_to[W: Writer](self, mut writer: W):
        writer.write(
            self.protocol,
            whitespace,
            self.status_code,
            whitespace,
            self.status_text,
            lineBreak,
        )

        if HeaderKey.DATE not in self.headers:
            var current_time = get_date_timestamp()
            write_header(writer, HeaderKey.DATE, current_time)

        self.headers.write_to(writer)

        writer.write(lineBreak)
        writer.write(to_string(self.body_raw))

    fn encode(owned self) -> Bytes:
        """Encodes response as bytes.

        This method consumes the data in this request and it should
        no longer be considered valid.
        """
        var writer = ByteWriter()
        writer.write(
            self.protocol,
            whitespace,
            String(self.status_code),
            whitespace,
            self.status_text,
            lineBreak,
        )
        writer.write(self.headers, lineBreak)

        # TODO: Changed line from taken code from lightbug_http
        # as it was causing a segfault. The original code was:
        # writer.consuming_write(self^.body_raw)
        writer.write_bytes(self.body_raw)
        return writer.consume()

    fn __str__(self) -> String:
        output = String()
        self.write_to(output)
        return output

