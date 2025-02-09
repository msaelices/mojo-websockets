from base64 import b64encode
from collections import Dict, Optional
from memory import Span
from utils import StringSlice

from websockets.aliases import Bytes, Duration, DEFAULT_BUFFER_SIZE
from websockets.libc import AF_INET6
from websockets.logger import logger
from websockets.utils.bytes import byte, bytes
from websockets.utils.string import (
    ByteReader,
    ByteWriter,
    BytesConstant,
    is_newline,
    is_space,
    LINE_BREAK,
    N_CHAR,
    R_CHAR,
    HTTP11,
    SLASH,
    to_string,
    WHITESPACE,
)
from websockets.utils.time import now
from websockets.utils.uri import URI
from websockets.net import (
    TCPAddr,
    TCPConnection,
    get_address_info,
    addrinfo_macos,
    addrinfo_unix,
)


struct HeaderKey:
    alias CONNECTION = "connection"
    alias CONTENT_TYPE = "content-type"
    alias CONTENT_LENGTH = "content-length"
    alias CONTENT_ENCODING = "content-encoding"
    alias TRANSFER_ENCODING = "transfer-encoding"
    alias DATE = "date"
    alias LOCATION = "location"
    alias HOST = "host"
    alias SERVER = "server"
    alias SET_COOKIE = "set-cookie"
    alias COOKIE = "cookie"


struct StatusCode:
    alias OK = 200
    alias MOVED_PERMANENTLY = 301
    alias FOUND = 302
    alias TEMPORARY_REDIRECT = 307
    alias PERMANENT_REDIRECT = 308
    alias NOT_FOUND = 404
    alias INTERNAL_ERROR = 500


@value
struct Header(Writable, Stringable):
    var key: String
    var value: String

    fn __str__(self) -> String:
        return String.write(self)

    fn write_to[T: Writer, //](self, mut writer: T):
        writer.write(self.key + ": ", self.value, LINE_BREAK)


@always_inline
fn write_header[W: Writer](mut writer: W, key: String, value: String):
    writer.write(key + ": ", value, LINE_BREAK)


@always_inline
fn write_header(mut writer: ByteWriter, key: String, mut value: String):
    var k = key + ": "
    writer.write(k)
    writer.write(value)
    writer.write(LINE_BREAK)


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
        if (
            address.isa[addrinfo_macos]()
            and address[addrinfo_macos].ai_family == AF_INET6
        ):
            host_header = "[{}]".format(host)
        elif (
            address.isa[addrinfo_unix]()
            and address[addrinfo_unix].ai_family == AF_INET6
        ):
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

    fn __eq__(self, other: Headers) -> Bool:
        for item in self._inner.items():
            key = item[].key
            value = item[].value
            if key not in other._inner or other._inner.get(key) != value:
                return False
        return True

    fn __ne__(self, other: Self) -> Bool:
        return not (self == other)

    @always_inline
    fn __contains__(self, key: String) -> Bool:
        return key.lower() in self._inner

    @always_inline
    fn __getitem__(self, key: String) raises -> String:
        return self._inner[key.lower()]

    @always_inline
    fn __setitem__(mut self, key: String, value: String):
        self._inner[key.lower()] = value

    fn __str__(self) -> String:
        return String.write(self)

    @always_inline
    fn empty(self) -> Bool:
        return len(self._inner) == 0

    @always_inline
    fn get(self, key: String) -> Optional[String]:
        return self._inner.get(key.lower())

    fn content_length(self) -> Int:
        try:
            return Int(self[HeaderKey.CONTENT_LENGTH])
        except:
            return 0

    fn parse_raw(mut self, mut r: ByteReader) raises -> (String, String, String):
        var first_byte = r.peek()
        if not first_byte:
            raise Error(
                "Headers.parse_raw: Failed to read first byte from response header"
            )

        var first = r.read_word()
        if not r.available():
            raise Error("Failed to read first word from request line")
        r.increment()
        var second = r.read_word()
        if not r.available():
            raise Error("Failed to read second word from request line")
        r.increment()
        var third = r.read_line()

        while r.available() and not is_newline(r.peek()):
            var key = r.read_until(BytesConstant.COLON)
            r.increment()
            if is_space(r.peek()):
                r.increment()
            var value = r.read_line()
            var k = to_string(key).lower()
            if k == HeaderKey.SET_COOKIE:
                continue

            self._inner[k] = to_string(value)
        return (to_string(first), to_string(second), to_string(third))

    fn write_to[T: Writer, //](self, mut writer: T):
        for header in self._inner.items():
            write_header(writer, header[].key, header[].value)

    fn remove(mut self, key: String) raises -> None:
        _ = self._inner.pop(key.lower())


@value
struct HTTPRequest(Writable, Stringable):
    var headers: Headers
    var uri: URI
    var body_raw: Bytes

    var method: String
    var protocol: String

    var timeout: Duration

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
        if HeaderKey.CONNECTION not in self.headers:
            self.headers[HeaderKey.CONNECTION] = "keep-alive"
        if HeaderKey.HOST not in self.headers and uri.host:
            self.headers[HeaderKey.HOST] = uri.host

    fn __str__(self) -> String:
        return String.write(self)

    fn __eq__(self, other: Self) raises -> Bool:
        return (
            self.method == other.method
            and self.uri == other.uri
            and self.protocol == other.protocol
            and self.headers == other.headers
            and String(self.body_raw) == String(other.body_raw)
        )

    fn __ne__(self, other: Self) raises -> Bool:
        return not (self == other)

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
    fn read_body(
        mut self, mut r: ByteReader, content_length: Int, max_body_size: Int
    ) raises -> None:
        if content_length > max_body_size:
            raise Error("Request body too large")

        self.body_raw = Bytes(r.read_bytes(content_length))

    fn write_to[T: Writer, //](self, mut writer: T):
        path = self.uri.path if len(self.uri.path) > 1 else SLASH
        if len(self.uri.query_string) > 0:
            path.write("?", self.uri.query_string)

        writer.write(
            self.method,
            WHITESPACE,
            path,
            WHITESPACE,
            self.protocol,
            LINE_BREAK,
            self.headers,
            LINE_BREAK,
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
            WHITESPACE,
            path,
            WHITESPACE,
            self.protocol,
            LINE_BREAK,
            self.headers,
            LINE_BREAK,
        )
        writer.consuming_write(self^.body_raw)
        return writer.consume()

    @staticmethod
    fn from_bytes(
        addr: String, max_body_size: Int, b: Span[Byte]
    ) raises -> (HTTPRequest, Int):
        var reader = ByteReader(b)
        var headers = Headers()
        var method: String
        var protocol: String
        var uri: String
        try:
            var rest = headers.parse_raw(reader)
            method, uri, protocol = rest[0], rest[1], rest[2]
        except e:
            raise Error(
                "HTTPRequest.from_bytes: Failed to parse request headers: " + String(e)
            )

        var content_length = headers.content_length()
        if content_length > 0 and max_body_size > 0 and content_length > max_body_size:
            raise Error("HTTPRequest.from_bytes: Request body too large.")

        var request = HTTPRequest(
            URI.parse(addr + uri),
            headers=headers,
            method=method,
            protocol=protocol,
        )
        try:
            request.read_body(reader, content_length, max_body_size)
        except e:
            raise Error(
                "HTTPRequest.from_bytes: Failed to read request body: " + String(e)
            )

        return request, reader.read_pos


@value
struct HTTPResponse(Writable, Stringable):
    var headers: Headers
    var body_raw: Bytes

    var status_code: Int
    var status_text: String
    var protocol: String

    fn __init__(
        out self,
        status_code: Int,
        status_text: String,
        headers: Headers,
        body_bytes: Span[Byte],
        protocol: String = HTTP11,
    ):
        self.headers = headers
        self.status_code = status_code
        self.status_text = status_text
        self.protocol = protocol
        self.body_raw = Bytes(body_bytes)

    fn __init__(
        out self,
        mut reader: ByteReader,
        headers: Headers = Headers(),
        status_code: Int = 200,
        status_text: String = "OK",
        protocol: String = HTTP11,
    ) raises:
        self.headers = headers
        self.status_code = status_code
        self.status_text = status_text
        self.protocol = protocol
        self.body_raw = Bytes(reader.read_bytes())

    fn __str__(self) -> String:
        return String.write(self)

    fn get_body(self) -> StringSlice[__origin_of(self.body_raw)]:
        return StringSlice(unsafe_from_utf8=Span(self.body_raw))

    @always_inline
    fn set_connection_close(mut self):
        self.headers[HeaderKey.CONNECTION] = "close"

    fn connection_close(self) -> Bool:
        var result = self.headers.get(HeaderKey.CONNECTION)
        if not result:
            return False
        return result.value() == "close"

    @always_inline
    fn set_connection_keep_alive(mut self):
        self.headers[HeaderKey.CONNECTION] = "keep-alive"

    @always_inline
    fn set_content_length(mut self, l: Int):
        self.headers[HeaderKey.CONTENT_LENGTH] = String(l)

    @always_inline
    fn content_length(self) -> Int:
        try:
            return Int(self.headers[HeaderKey.CONTENT_LENGTH])
        except:
            return 0

    @always_inline
    fn is_redirect(self) -> Bool:
        return (
            self.status_code == StatusCode.MOVED_PERMANENTLY
            or self.status_code == StatusCode.FOUND
            or self.status_code == StatusCode.TEMPORARY_REDIRECT
            or self.status_code == StatusCode.PERMANENT_REDIRECT
        )

    @always_inline
    fn read_body(mut self, mut r: ByteReader) raises -> None:
        self.body_raw = Bytes(r.read_bytes(self.content_length()))
        self.set_content_length(len(self.body_raw))

    fn read_chunks(mut self, chunks: Span[Byte]) raises:
        var reader = ByteReader(chunks)
        while True:
            var size = atol(StringSlice(unsafe_from_utf8=reader.read_line()), 16)
            if size == 0:
                break
            var data = reader.read_bytes(size)
            reader.skip_carriage_return()
            self.set_content_length(self.content_length() + len(data))
            self.body_raw += Bytes(data)

    fn write_to[T: Writer](self, mut writer: T):
        writer.write(
            self.protocol,
            WHITESPACE,
            self.status_code,
            WHITESPACE,
            self.status_text,
            LINE_BREAK,
        )
        writer.write(self.headers, LINE_BREAK, to_string(self.body_raw))

    fn encode(owned self) -> Bytes:
        """Encodes response as bytes.

        This method consumes the data in this request and it should
        no longer be considered valid.
        """
        var writer = ByteWriter()
        writer.write(
            self.protocol,
            WHITESPACE,
            String(self.status_code),
            WHITESPACE,
            self.status_text,
            LINE_BREAK,
        )
        if HeaderKey.DATE not in self.headers:
            try:
                write_header(writer, HeaderKey.DATE, String(now(utc=True)))
            except:
                pass
        writer.write(self.headers, LINE_BREAK)
        writer.consuming_write(self^.body_raw)
        return writer.consume()

    @staticmethod
    fn from_bytes(b: Span[Byte]) raises -> HTTPResponse:
        var reader = ByteReader(b)
        var headers = Headers()
        var protocol: String
        var status_code: String
        var status_text: String

        try:
            var properties = headers.parse_raw(reader)
            protocol, status_code, status_text = (
                properties[0],
                properties[1],
                properties[2],
            )
        except e:
            raise Error("Failed to parse response headers: " + String(e))

        try:
            return HTTPResponse(
                reader=reader,
                headers=headers,
                protocol=protocol,
                status_code=Int(status_code),
                status_text=status_text,
            )
        except e:
            logger.error(e)
            raise Error("Failed to read request body")

    @staticmethod
    fn from_bytes(b: Span[Byte], conn: TCPConnection) raises -> HTTPResponse:
        var reader = ByteReader(b)
        var headers = Headers()
        var protocol: String
        var status_code: String
        var status_text: String

        try:
            var properties = headers.parse_raw(reader)
            protocol, status_code, status_text = (
                properties[0],
                properties[1],
                properties[2],
            )
            reader.skip_carriage_return()
        except e:
            raise Error("Failed to parse response headers: " + String(e))

        var response = HTTPResponse(
            status_code=Int(status_code),
            status_text=status_text,
            headers=headers,
            body_bytes=Bytes(),
            protocol=protocol,
        )

        var transfer_encoding = response.headers.get(HeaderKey.TRANSFER_ENCODING)
        if transfer_encoding and transfer_encoding.value() == "chunked":
            var b = Bytes(reader.read_bytes())
            var buff = Bytes(capacity=DEFAULT_BUFFER_SIZE)
            try:
                while conn.read(buff) > 0:
                    b += buff

                    if (
                        buff[-5] == byte("0")
                        and buff[-4] == byte("\r")
                        and buff[-3] == byte("\n")
                        and buff[-2] == byte("\r")
                        and buff[-1] == byte("\n")
                    ):
                        break

                    buff.resize(0)
                response.read_chunks(b)
                return response
            except e:
                logger.error(e)
                raise Error("Failed to read chunked response.")

        try:
            response.read_body(reader)
            return response
        except e:
            logger.error(e)
            raise Error("Failed to read request body: ")
