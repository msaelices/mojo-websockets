from memory import memcpy, Span

from websockets.aliases import Bytes, DEFAULT_BUFFER_SIZE
from websockets.utils.bytes import byte


alias SLASH = "/"
alias HTTP = "http"
alias HTTPS = "https"
alias HTTP11 = "HTTP/1.1"
alias HTTP10 = "HTTP/1.0"
alias WS = "ws"
alias WSS = "wss"

alias R_CHAR = "\r"
alias N_CHAR = "\n"
alias LINE_BREAK = R_CHAR + N_CHAR
alias COLON_CHAR = ":"

alias EMPTY_STRING = ""
alias WHITESPACE = " "
alias WHITESPACE_byte = ord(WHITESPACE)
alias TAB = "\t"

alias EndOfReaderError = "No more bytes to read."
alias OutOfBoundsError = "Tried to read past the end of the ByteReader."


struct BytesConstant:
    alias WHITESPACE = byte(WHITESPACE)
    alias COLON = byte(COLON_CHAR)
    alias R_CHAR = byte(R_CHAR)
    alias N_CHAR = byte(N_CHAR)


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


struct ByteWriter(Writer):
    var _inner: Bytes

    fn __init__(out self, capacity: Int = DEFAULT_BUFFER_SIZE):
        self._inner = Bytes(capacity=capacity)

    @always_inline
    fn write_bytes(mut self, bytes: Span[Byte]) -> None:
        """Writes the contents of `bytes` into the internal buffer.

        Args:
            bytes: The bytes to write.
        """
        self._inner.extend(bytes)

    fn write[*Ts: Writable](mut self, *args: *Ts) -> None:
        """Write data to the `Writer`.

        Parameters:
            Ts: The types of data to write.

        Args:
            args: The data to write.
        """

        @parameter
        fn write_arg[T: Writable](arg: T):
            arg.write_to(self)

        args.each[write_arg]()

    @always_inline
    fn consuming_write(mut self, owned b: Bytes):
        self._inner.extend(b^)

    @always_inline
    fn consuming_write(mut self, owned s: String):
        # kind of cursed but seems to work?
        _ = s._buffer.pop()
        self._inner.extend(s._buffer^)
        s._buffer = s._buffer_type()

    @always_inline
    fn write_byte(mut self, b: Byte):
        self._inner.append(b)

    fn consume(mut self) -> Bytes:
        var ret = self._inner^
        self._inner = Bytes()
        return ret^


struct ByteReader[origin: Origin]:
    var _inner: Span[Byte, origin]
    var read_pos: Int

    fn __init__(out self, ref b: Span[Byte, origin]):
        self._inner = b
        self.read_pos = 0

    @always_inline
    fn available(self) -> Bool:
        return self.read_pos < len(self._inner)

    fn __len__(self) -> Int:
        return len(self._inner) - self.read_pos

    fn peek(self) raises -> Byte:
        if not self.available():
            raise EndOfReaderError
        return self._inner[self.read_pos]

    fn read_bytes(mut self, n: Int = -1) raises -> Span[Byte, origin]:
        var count = n
        var start = self.read_pos
        if n == -1:
            count = len(self)

        if start + count > len(self._inner):
            raise OutOfBoundsError

        self.read_pos += count
        return self._inner[start : start + count]

    fn read_until(mut self, char: Byte) -> Span[Byte, origin]:
        var start = self.read_pos
        for i in range(start, len(self._inner)):
            if self._inner[i] == char:
                break
            self.increment()

        return self._inner[start : self.read_pos]

    @always_inline
    fn read_word(mut self) -> Span[Byte, origin]:
        return self.read_until(BytesConstant.WHITESPACE)

    fn read_line(mut self) -> Span[Byte, origin]:
        var start = self.read_pos
        for i in range(start, len(self._inner)):
            if is_newline(self._inner[i]):
                break
            self.increment()

        # If we are at the end of the buffer, there is no newline to check for.
        var ret = self._inner[start : self.read_pos]
        if not self.available():
            return ret

        if self._inner[self.read_pos] == BytesConstant.R_CHAR:
            self.increment(2)
        else:
            self.increment()
        return ret

    @always_inline
    fn skip_WHITESPACE(mut self):
        for i in range(self.read_pos, len(self._inner)):
            if is_space(self._inner[i]):
                self.increment()
            else:
                break

    @always_inline
    fn skip_carriage_return(mut self):
        for i in range(self.read_pos, len(self._inner)):
            if self._inner[i] == BytesConstant.R_CHAR:
                self.increment(2)
            else:
                break

    @always_inline
    fn increment(mut self, v: Int = 1):
        self.read_pos += v

    @always_inline
    fn consume(owned self, bytes_len: Int = -1) -> Bytes:
        return Bytes(self^._inner[self.read_pos : self.read_pos + len(self) + 1])


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


fn compare_case_insensitive(a: Bytes, b: Bytes) -> Bool:
    if len(a) != len(b):
        return False
    for i in range(len(a) - 1):
        if (a[i] | 0x20) != (b[i] | 0x20):
            return False
    return True


@always_inline
fn is_newline(b: Byte) -> Bool:
    return b == BytesConstant.N_CHAR or b == BytesConstant.R_CHAR


@always_inline
fn is_space(b: Byte) -> Bool:
    return b == BytesConstant.WHITESPACE
