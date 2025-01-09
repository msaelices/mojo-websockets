from memory import memcpy, Span

from ..aliases import Bytes, DEFAULT_BUFFER_SIZE


alias SLASH = "/"
alias HTTP = "http"
alias HTTPS = "https"
alias HTTP11 = "HTTP/1.1"
alias HTTP10 = "HTTP/1.0"
alias WS = "ws"
alias WSS = "wss"

alias strMethodGet = "GET"

alias rChar = "\r"
alias nChar = "\n"
alias lineBreak = rChar + nChar
alias colonChar = ":"

alias empty_string = ""
alias whitespace = " "
alias whitespace_byte = ord(whitespace)
alias tab = "\t"
alias tab_byte = ord(tab)


struct BytesConstant:
    alias whitespace = byte(whitespace)
    alias colon = byte(colonChar)
    alias rChar = byte(rChar)
    alias nChar = byte(nChar)


@value
struct NetworkType:
    var value: String

    alias empty = NetworkType("")
    alias tcp = NetworkType("tcp")
    alias tcp4 = NetworkType("tcp4")
    alias tcp6 = NetworkType("tcp6")
    alias udp = NetworkType("udp")
    alias udp4 = NetworkType("udp4")
    alias udp6 = NetworkType("udp6")
    alias ip = NetworkType("ip")
    alias ip4 = NetworkType("ip4")
    alias ip6 = NetworkType("ip6")
    alias unix = NetworkType("unix")


@value
struct ConnType:
    var value: String

    alias empty = ConnType("")
    alias http = ConnType("http")
    alias websocket = ConnType("websocket")


@value
struct RequestMethod:
    var value: String

    alias get = RequestMethod("GET")
    alias post = RequestMethod("POST")
    alias put = RequestMethod("PUT")
    alias delete = RequestMethod("DELETE")
    alias head = RequestMethod("HEAD")
    alias patch = RequestMethod("PATCH")
    alias options = RequestMethod("OPTIONS")


@value
struct CharSet:
    var value: String

    alias utf8 = CharSet("utf-8")


@value
struct MediaType:
    var value: String

    alias empty = MediaType("")
    alias plain = MediaType("text/plain")
    alias json = MediaType("application/json")


@value
struct Message:
    var type: String

    alias empty = Message("")
    alias http_start = Message("http.response.start")


struct ByteWriter:
    var _inner: Bytes

    fn __init__(out self, capacity: Int = DEFAULT_BUFFER_SIZE):
        self._inner = Bytes(capacity=capacity)

    @always_inline
    fn write(mut self, owned b: Bytes):
        self._inner.extend(b^)

    @always_inline
    fn write(mut self, inout s: String):
        # kind of cursed but seems to work?
        _ = s._buffer.pop()
        self._inner.extend(s._buffer^)
        s._buffer = s._buffer_type()

    @always_inline
    fn write(mut self, s: StringLiteral):
        var str = String(s)
        self.write(str)

    @always_inline
    fn write(mut self, b: Byte):
        self._inner.append(b)

    fn consume(mut self) -> Bytes:
        var ret = self._inner^
        self._inner = Bytes()
        return ret^


struct ByteReader:
    var _inner: Bytes
    var read_pos: Int

    fn __init__(out self, owned b: Bytes):
        self._inner = b^
        self.read_pos = 0

    @always_inline
    fn has_next(self) -> Bool:
        return self.read_pos < len(self._inner)

    fn peek(self) -> Byte:
        if not self.has_next():
            return 0
        return self._inner[self.read_pos]

    fn read_until(mut self, char: Byte) -> Bytes:
        var start = self.read_pos
        while self.peek() != char and self.has_next():
            self.increment()
        return self._inner[start : self.read_pos]

    @always_inline
    fn read_word(mut self) -> Bytes:
        return self.read_until(BytesConstant.whitespace)

    fn read_line(mut self) -> Bytes:
        var start = self.read_pos
        while not is_newline(self.peek()) and self.has_next():
            self.increment()
        var ret = self._inner[start : self.read_pos]
        var remaining = len(self._inner) - self.read_pos - 1
        if self.peek() == BytesConstant.rChar:
            self.increment(min(2, remaining))
        else:
            self.increment(min(1, remaining))
        return ret

    @always_inline
    fn skip_whitespace(mut self):
        while is_space(self.peek()) and self.has_next():
            self.increment()

    @always_inline
    fn increment(mut self, v: Int = 1):
        self.read_pos += v

    @always_inline
    fn consume(mut self, inout buffer: Bytes):
        var pos = self.read_pos
        self.read_pos = -1
        var read_len = len(self._inner) - pos
        buffer.resize(read_len, 0)
        memcpy(buffer.data, self._inner.data + pos, read_len)


fn to_string[T: Writer](mut writer: T) -> String:
    var s = String()
    s.write_to(writer)
    return s


fn to_string(b: Span[UInt8]) -> String:
    """Creates a String from a copy of the provided Span of bytes.

    Args:
        b: The Span of bytes to convert to a String.
    """
    var bytes = List[UInt8, True](b)
    bytes.append(0)
    return String(bytes^)


fn to_string(owned bytes: List[UInt8, True]) -> String:
    """Creates a String from the provided List of bytes.
    If you do not transfer ownership of the List, the List will be copied.

    Args:
        bytes: The List of bytes to convert to a String.
    """
    if bytes[-1] != 0:
        bytes.append(0)
    return String(bytes^)


@always_inline
fn byte(s: String) -> Byte:
    return ord(s)


@always_inline
fn bytes(s: String) -> Bytes:
    return s.as_bytes()


@always_inline
fn bytes_equal(a: Bytes, b: Bytes) -> Bool:
    return to_string(a) == to_string(b)


fn compare_case_insensitive(a: Bytes, b: Bytes) -> Bool:
    if len(a) != len(b):
        return False
    for i in range(len(a) - 1):
        if (a[i] | 0x20) != (b[i] | 0x20):
            return False
    return True


@always_inline
fn is_newline(b: Byte) -> Bool:
    return b == BytesConstant.nChar or b == BytesConstant.rChar


@always_inline
fn is_space(b: Byte) -> Bool:
    return b == BytesConstant.whitespace
