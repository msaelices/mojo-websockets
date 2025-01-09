from collections import Dict

from libc import Bytes, AF_INET6
from small_time.small_time import now

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
from .net import TCPAddr, get_address_info, addrinfo_macos, addrinfo_unix

struct HeaderKey:
    alias CONNECTION = "Connection"
    alias CONTENT_TYPE = "Content-type"
    alias CONTENT_LENGTH = "Content-length"
    alias CONTENT_ENCODING = "Content-encoding"
    alias DATE = "Date"


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
    fn __setitem__(mut self, key: String, value: String):
        self._inner[key.lower()] = value

    fn __eq__(self, other: Self) -> Bool:
        if len(self._inner) != len(other._inner):
            return False
        try:
            for item in self._inner.items():
                key = item[].key
                value = item[].value
                if key not in other._inner or other._inner[key] != value:
                    return False
        except:
            return False
        return True

    fn __ne__(self, other: Self) -> Bool:
        return not self.__eq__(other)

    fn content_length(self) -> Int:
        if HeaderKey.CONTENT_LENGTH not in self:
            return 0
        try:
            return int(self[HeaderKey.CONTENT_LENGTH])
        except:
            return 0

    fn parse_raw(
        mut self, inout r: ByteReader
    ) raises -> (String, String, String):
        var first_byte = r.peek()
        if not first_byte:
            raise Error("Failed to read first byte from request line")

        var first = r.read_word()
        if not r.has_next():
            raise Error("Failed to read second word from request line")
        r.increment()
        var second = r.read_word()
        if not r.has_next():
            raise Error("Failed to read third word from request line")
        r.increment()
        var third = r.read_line()

        while not is_newline(r.peek()) and r.has_next():
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

    fn encode_to(mut self, mut writer: ByteWriter):
        for header in self._inner.items():
            write_header(writer, header[].key, header[].value)

    fn remove(mut self, key: String) raises -> None:
        _ = self._inner.pop(key.lower())

    fn __str__(self) -> String:
        var output = String()
        self.write_to(output)
        return output


@value
struct HTTPRequest(Writable, Stringable):
    var headers: Headers
    var body_raw: Bytes
    var uri: URI

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
            raise Error("ValueError: Failed to parse request headers: " + e.__str__())

        var uri = URI.parse_raises(addr + uri_str)

        var content_length = headers.content_length()

        if (
            content_length > 0
            and max_body_size > 0
            and content_length > max_body_size
        ):
            raise Error("Request body too large")

        var request = HTTPRequest(
            uri, headers=headers, method=method, protocol=protocol
        )

        try:
            request.read_body(reader, content_length, max_body_size)
        except e:
            raise Error("Failed to read request body: " + e.__str__())

        return request

    fn __init__(
        out self,
        uri: URI,
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
        self.uri = uri
        self.body_raw = body
        self.server_is_tls = server_is_tls
        self.timeout = timeout
        if HeaderKey.CONNECTION not in self.headers:
            self.set_connection_close()

    fn set_connection_close(mut self):
        self.headers[HeaderKey.CONNECTION] = "close"

    fn set_content_length(mut self, l: Int):
        self.headers[HeaderKey.CONTENT_LENGTH] = str(l)

    fn connection_close(self) -> Bool:
        return self.headers[HeaderKey.CONNECTION] == "close"

    @always_inline
    fn read_body(
        mut self, inout r: ByteReader, content_length: Int, max_body_size: Int
    ) raises -> None:
        if content_length > max_body_size:
            raise Error("Request body too large")

        r.consume(self.body_raw)

    fn write_to[W: Writer](self, mut writer: W):
        writer.write(
            self.method,
            whitespace,
            self.uri.get_path() if len(self.uri.path) > 1 else SLASH,
            whitespace,
            self.protocol,
            lineBreak,
        )

        self.headers.write_to(writer)
        writer.write(lineBreak)
        writer.write(to_string(self.body_raw))

    fn _encoded(mut self) -> Bytes:
        """Encodes request as bytes.

        This method consumes the data in this request and it should
        no longer be considered valid.
        """
        var writer = ByteWriter()
        writer.write(self.method)
        writer.write(whitespace)
        var path = self.uri.get_path() if len(self.uri.path) > 1 else SLASH
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
            status_code=int(status_code),
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
        self.headers[HeaderKey.CONTENT_LENGTH] = str(l)

    @always_inline
    fn read_body(mut self, inout r: ByteReader) raises -> None:
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

    fn _encoded(mut self) -> Bytes:
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

        if HeaderKey.DATE not in self.headers:
            # TODO: Use UTC time
            var current_time = get_date_timestamp()
            write_header(writer, HeaderKey.DATE, current_time)

        self.headers.encode_to(writer)

        writer.write(lineBreak)
        writer.write(self.body_raw)

        return writer.consume()

    fn __str__(self) -> String:
        output = String()
        self.write_to(output)
        return output

