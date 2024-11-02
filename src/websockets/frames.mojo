from bit import byte_swap
from collections import Dict, Optional
from memory import bitcast, UnsafePointer
from utils import StringRef

from websockets.utils.string import Bytes

alias Opcode = Int

# Opcodes for WebSocket frames
alias OP_CONT = 0x00
alias OP_TEXT = 0x01
alias OP_BINARY = 0x02
alias OP_CLOSE = 0x08
alias OP_PING = 0x09
alias OP_PONG = 0x0A

alias DATA_OPCODES = (OP_CONT, OP_TEXT, OP_BINARY)
alias CTRL_OPCODES = (OP_CLOSE, OP_PING, OP_PONG)

# Close codes
alias CLOSE_CODE_NORMAL_CLOSURE = 1000
alias CLOSE_CODE_GOING_AWAY = 1001
alias CLOSE_CODE_PROTOCOL_ERROR = 1002
alias CLOSE_CODE_UNSUPPORTED_DATA = 1003
# 1004 is reserved
alias CLOSE_CODE_NO_STATUS_RCVD = 1005
alias CLOSE_CODE_ABNORMAL_CLOSURE = 1006
alias CLOSE_CODE_INVALID_DATA = 1007
alias CLOSE_CODE_POLICY_VIOLATION = 1008
alias CLOSE_CODE_MESSAGE_TOO_BIG = 1009
alias CLOSE_CODE_MANDATORY_EXTENSION = 1010
alias CLOSE_CODE_INTERNAL_ERROR = 1011
alias CLOSE_CODE_SERVICE_RESTART = 1012
alias CLOSE_CODE_TRY_AGAIN_LATER = 1013
alias CLOSE_CODE_BAD_GATEWAY = 1014
alias CLOSE_CODE_TLS_HANDSHAKE = 1015

# Close code that are allowed in a close frame.
alias EXTERNAL_CLOSE_CODES = (
    CLOSE_CODE_NORMAL_CLOSURE,
    CLOSE_CODE_GOING_AWAY,
    CLOSE_CODE_PROTOCOL_ERROR,
    CLOSE_CODE_UNSUPPORTED_DATA,
    CLOSE_CODE_INVALID_DATA,
    CLOSE_CODE_POLICY_VIOLATION,
    CLOSE_CODE_MESSAGE_TOO_BIG,
    CLOSE_CODE_MANDATORY_EXTENSION,
    CLOSE_CODE_INTERNAL_ERROR,
    CLOSE_CODE_SERVICE_RESTART,
    CLOSE_CODE_TRY_AGAIN_LATER,
    CLOSE_CODE_BAD_GATEWAY,
)

# OK codes in a closed frame.
alias OK_CLOSE_CODES = (
    CLOSE_CODE_NORMAL_CLOSURE,
    CLOSE_CODE_GOING_AWAY,
    CLOSE_CODE_NO_STATUS_RCVD,
)


@always_inline
fn get_op_code_name(code: Int) raises -> String:
    var name: String
    if code == OP_CONT:
        name = "CONT"
    elif code == OP_TEXT:
        name = "TEXT"
    elif code == OP_BINARY:
        name = "BINARY"
    elif code == OP_CLOSE:
        name = "CLOSE"
    elif code == OP_PING:
        name = "PING"
    elif code == OP_PONG:
        name = "PONG"
    else:
        name = "UNKNOWN"
    return name


@always_inline
fn get_close_code_name(code: Int) raises -> String:
    var name: String
    if code == CLOSE_CODE_NORMAL_CLOSURE:
        name = "NORMAL_CLOSURE"
    elif code == CLOSE_CODE_GOING_AWAY:
        name = "GOING_AWAY"
    elif code == CLOSE_CODE_PROTOCOL_ERROR:
        name = "PROTOCOL_ERROR"
       elif code == CLOSE_CODE_UNSUPPORTED_DATA:
            name = "UNSUPPORTED_DATA"
        elif code == CLOSE_CODE_NO_STATUS_RCVD:
            name = "NO_STATUS_RCVD"
        elif code == CLOSE_CODE_ABNORMAL_CLOSURE:
            name = "ABNORMAL_CLOSURE"
        elif code == CLOSE_CODE_INVALID_DATA:
            name = "INVALID_DATA"
        elif code == CLOSE_CODE_POLICY_VIOLATION:
            name = "POLICY_VIOLATION"
        elif code == CLOSE_CODE_MESSAGE_TOO_BIG:
            name = "MESSAGE_TOO_BIG"
        elif code == CLOSE_CODE_MANDATORY_EXTENSION:
            name = "MANDATORY_EXTENSION"
        elif code == CLOSE_CODE_INTERNAL_ERROR:
            name = "INTERNAL_ERROR"
        elif code == CLOSE_CODE_SERVICE_RESTART:
            name = "SERVICE_RESTART"
        elif code == CLOSE_CODE_TRY_AGAIN_LATER:
            name = "TRY_AGAIN_LATER"
        elif code == CLOSE_CODE_BAD_GATEWAY:
            name = "BAD_GATEWAY"
        elif code == CLOSE_CODE_TLS_HANDSHAKE:
            name = "TLS_HANDSHAKE"
        else:
            name = "UNKNOWN"
    return name


@always_inline
fn get_close_code_explanation(code: Int) raises -> String:
    var explanation: String
    if code == CLOSE_CODE_NORMAL_CLOSURE:
        explanation = "OK"
    elif code == CLOSE_CODE_GOING_AWAY:
        explanation = "going away"
    elif code == CLOSE_CODE_PROTOCOL_ERROR:
        explanation = "protocol error"
    elif code == CLOSE_CODE_UNSUPPORTED_DATA:
        explanation = "unsupported data"
    elif code == CLOSE_CODE_NO_STATUS_RCVD:
        explanation = "no status received [internal]"
    elif code == CLOSE_CODE_ABNORMAL_CLOSURE:
        explanation = "abnormal closure [internal]"
    elif code == CLOSE_CODE_INVALID_DATA:
        explanation = "invalid frame payload data"
    elif code == CLOSE_CODE_POLICY_VIOLATION:
        explanation = "policy violation"
    elif code == CLOSE_CODE_MESSAGE_TOO_BIG:
        explanation = "message too big"
    elif code == CLOSE_CODE_MANDATORY_EXTENSION:
        explanation = "mandatory extension"
    elif code == CLOSE_CODE_INTERNAL_ERROR:
        explanation = "internal error"
    elif code == CLOSE_CODE_SERVICE_RESTART:
        explanation = "service restart"
    elif code == CLOSE_CODE_TRY_AGAIN_LATER:
        explanation = "try again later"
    elif code == CLOSE_CODE_BAD_GATEWAY:
        explanation = "bad gateway"
    elif code == CLOSE_CODE_TLS_HANDSHAKE:
        explanation = "TLS handshake failure [internal]"
    else:
        explanation = "unknown"
    return explanation


@value
struct Frame(Writable, Stringable):
    """
    WebSocket frame.

    Attributes:
        opcode: Opcode.
        data: Payload data.
        fin: FIN bit.
        rsv1: RSV1 bit.
        rsv2: RSV2 bit.
        rsv3: RSV3 bit.

    Only these fields are needed. The MASK bit, payload length and masking-key
    are handled on the fly when parsing and serializing frames.
    """

    var opcode: Opcode
    var data: Bytes
    var fin: Bool
    var rsv1: Bool
    var rsv2: Bool
    var rsv3: Bool

    fn __init__(inout self, opcode: Opcode, data: Bytes, fin: Bool = True):
        self.opcode = opcode
        self.data = data
        self.fin = fin
        # reserved flags not used in the current websockets protocol
        self.rsv1 = False
        self.rsv2 = False
        self.rsv3 = False

    fn write_to[W: Writer](self, inout writer: W):
        """
        Return a human-readable representation of a frame.
        """
        var coding: String = ""
        var data: String

        try:
            length = "{} byte{}".format(
               len(self.data),
               "" if len(self.data) == 1 else "s",
            )
        except:
            length = "Error"
        non_final = "" if self.fin else "continued"

        if self.opcode == OP_TEXT:
            # Decoding only the beginning and the end is needlessly hard.
            # Decode the entire payload then elide later if necessary.
            data = self._data_as_text()
            coding = "text"
        elif self.opcode == OP_BINARY:
            # We'll show at most the first 16 bytes and the last 8 bytes.
            # Encode just what we need, plus two dummy bytes to elide later.
            try:
                data = self._data_as_binary()
                coding = "binary"
            except:
                data = "Error"
        elif self.opcode == OP_CLOSE:
            try:
                data = str(Close.parse(self.data))
            except:
                data = "Error"
        elif self.data:
            # We don't know if a Continuation frame contains text or binary.
            # Ping and Pong frames could contain UTF-8.
            # Attempt to decode as UTF-8 and display it as text; fallback to
            # binary. If self.data is a memoryview, it has no decode() method,
            # which raises AttributeError.
            data = self._data_as_text()
            coding = "text"
            # except:
            #     data += _repr_binary(self.data)
            #     coding = "binary"
        else:
            data = "''"

        metadata = ", ".join(List(coding, length, non_final))

        try:
            repr_data = "'{}'".format(data) if coding == "text" else data
            writer.write(get_op_code_name(self.opcode), " ", repr_data, " [", metadata, "]")
        except:
            writer.write("Error")

    fn __str__(self) -> String:
        return String.write(self)

    @always_inline
    fn _data_as_text(self) -> String:
        """
        Return the data as a string.
        """
        return StringRef(self.data.unsafe_ptr(), len(self.data))

    @always_inline
    fn _data_as_binary(self) raises -> String:
        """
        Return the data as a string.
        """
        var s: String = ""
        for byte in self.data:
            s += "{} ".format(hex(ord(str(byte))))
        return s.strip()


@value
struct Close:
    """
    Code and reason for WebSocket close frames.

    Attributes:
        code: Close code.
        reason: Close reason.
    """

    var code: Int
    var reason: String

    fn __str__(self) raises -> String:
        """
        Return a human-readable representation of a close code and reason.

        """
        var explanation: String
        if 3000 <= self.code < 4000:
            explanation = "registered"
        elif 4000 <= self.code < 5000:
            explanation = "private use"
        else:
            explanation = get_close_code_explanation(self.code)
        result = "{} ({})".format(get_close_code_name(self.code), explanation)

        if self.reason:
            result = "{} {}".format(result, self.reason)

        return result

    @staticmethod
    fn parse(data: Bytes) raises -> Close:
        """
        Parse the payload of a close frame.

        Args:
            data: Payload of the close frame.

        Raises:
            ProtocolError: If data is ill-formed.
            UnicodeDecodeError: If the reason isn't valid UTF-8.

        """
        if len(data) >= 2:
            # TODO: Check if this is equivalent to struct.unpack("!H", data[:2])
            # code = byte_swap(rebind[UInt16](data[:2]))
            code = int(byte_swap(data.unsafe_ptr().bitcast[UInt16]()[]))
            # code = int(byte_swap(data[:2]))
            reason = String(data[2:] + Bytes(0))
            close = Close(code, reason)
            close.check()
            return close
        elif len(data) == 0:
            return Close(CLOSE_CODE_NO_STATUS_RCVD, "")
        else:
            raise Error("ProtocolError: close frame too short")

    fn serialize(self) raises -> Bytes:
        """
        Serialize the payload of a close frame.

        """
        self.check()
        # TODO: Check if this is equivalent to struct.pack("!H", self.code) + self.reason.encode()
        return Bytes(self.code) + self.reason.as_bytes()

    fn check(self) raises -> None:
        """
        Check that the close code has a valid value for a close frame.

        Raises:
            Error: If the close code is invalid.

        """
        if not (self.code in EXTERNAL_CLOSE_CODES or 3000 <= self.code < 5000):
            raise Error("ProtocolError: invalid status code: {}".format(self.code))

#
# BytesLike = bytes, bytearray, memoryview
#
#
# @dataclasses.dataclass
# class Frame:
#     """
#     WebSocket frame.
#
#     Attributes:
#         opcode: Opcode.
#         data: Payload data.
#         fin: FIN bit.
#         rsv1: RSV1 bit.
#         rsv2: RSV2 bit.
#         rsv3: RSV3 bit.
#
#     Only these fields are needed. The MASK bit, payload length and masking-key
#     are handled on the fly when parsing and serializing frames.
#
#     """
#
#     opcode: Opcode
#     data: Union[bytes, bytearray, memoryview]
#     fin: bool = True
#     rsv1: bool = False
#     rsv2: bool = False
#     rsv3: bool = False
#
#     # Configure if you want to see more in logs. Should be a multiple of 3.
#     MAX_LOG_SIZE = int(os.environ.get("WEBSOCKETS_MAX_LOG_SIZE", "75"))
#
#     def __str__(self) -> str:
#         """
#         Return a human-readable representation of a frame.
#
#         """
#         coding = None
#         length = f"{len(self.data)} byte{'' if len(self.data) == 1 else 's'}"
#         non_final = "" if self.fin else "continued"
#
#         if self.opcode is OP_TEXT:
#             # Decoding only the beginning and the end is needlessly hard.
#             # Decode the entire payload then elide later if necessary.
#             data = repr(bytes(self.data).decode())
#         elif self.opcode is OP_BINARY:
#             # We'll show at most the first 16 bytes and the last 8 bytes.
#             # Encode just what we need, plus two dummy bytes to elide later.
#             binary = self.data
#             if len(binary) > self.MAX_LOG_SIZE // 3:
#                 cut = (self.MAX_LOG_SIZE // 3 - 1) // 3  # by default cut = 8
#                 binary = b"".join([binary[: 2 * cut], b"\x00\x00", binary[-cut:]])
#             data = " ".join(f"{byte:02x}" for byte in binary)
#         elif self.opcode is OP_CLOSE:
#             data = str(Close.parse(self.data))
#         elif self.data:
#             # We don't know if a Continuation frame contains text or binary.
#             # Ping and Pong frames could contain UTF-8.
#             # Attempt to decode as UTF-8 and display it as text; fallback to
#             # binary. If self.data is a memoryview, it has no decode() method,
#             # which raises AttributeError.
#             try:
#                 data = repr(bytes(self.data).decode())
#                 coding = "text"
#             except (UnicodeDecodeError, AttributeError):
#                 binary = self.data
#                 if len(binary) > self.MAX_LOG_SIZE // 3:
#                     cut = (self.MAX_LOG_SIZE // 3 - 1) // 3  # by default cut = 8
#                     binary = b"".join([binary[: 2 * cut], b"\x00\x00", binary[-cut:]])
#                 data = " ".join(f"{byte:02x}" for byte in binary)
#                 coding = "binary"
#         else:
#             data = "''"
#
#         if len(data) > self.MAX_LOG_SIZE:
#             cut = self.MAX_LOG_SIZE // 3 - 1  # by default cut = 24
#             data = data[: 2 * cut] + "..." + data[-cut:]
#
#         metadata = ", ".join(filter(None, [coding, length, non_final]))
#
#         return f"{self.opcode.name} {data} [{metadata}]"
#
#     @classmethod
#     def parse(
#         cls,
#         read_exact: Callable[[int], Generator[None, None, bytes]],
#         *,
#         mask: bool,
#         max_size: int | None = None,
#         extensions: Sequence[extensions.Extension] | None = None,
#     ) -> Generator[None, None, Frame]:
#         """
#         Parse a WebSocket frame.
#
#         This is a generator-based coroutine.
#
#         Args:
#             read_exact: Generator-based coroutine that reads the requested
#                 bytes or raises an exception if there isn't enough data.
#             mask: Whether the frame should be masked i.e. whether the read
#                 happens on the server side.
#             max_size: Maximum payload size in bytes.
#             extensions: List of extensions, applied in reverse order.
#
#         Raises:
#             EOFError: If the connection is closed without a full WebSocket frame.
#             UnicodeDecodeError: If the frame contains invalid UTF-8.
#             PayloadTooBig: If the frame's payload size exceeds ``max_size``.
#             ProtocolError: If the frame contains incorrect values.
#
#         """
#         # Read the header.
#         data = yield from read_exact(2)
#         head1, head2 = struct.unpack("!BB", data)
#
#         # While not Pythonic, this is marginally faster than calling bool().
#         fin = True if head1 & 0b10000000 else False
#         rsv1 = True if head1 & 0b01000000 else False
#         rsv2 = True if head1 & 0b00100000 else False
#         rsv3 = True if head1 & 0b00010000 else False
#
#         try:
#             opcode = Opcode(head1 & 0b00001111)
#         except ValueError as exc:
#             raise ProtocolError("invalid opcode") from exc
#
#         if (True if head2 & 0b10000000 else False) != mask:
#             raise ProtocolError("incorrect masking")
#
#         length = head2 & 0b01111111
#         if length == 126:
#             data = yield from read_exact(2)
#             (length,) = struct.unpack("!H", data)
#         elif length == 127:
#             data = yield from read_exact(8)
#             (length,) = struct.unpack("!Q", data)
#         if max_size is not None and length > max_size:
#             raise PayloadTooBig(f"over size limit ({length} > {max_size} bytes)")
#         if mask:
#             mask_bytes = yield from read_exact(4)
#
#         # Read the data.
#         data = yield from read_exact(length)
#         if mask:
#             data = apply_mask(data, mask_bytes)
#
#         frame = cls(opcode, data, fin, rsv1, rsv2, rsv3)
#
#         if extensions is None:
#             extensions = []
#         for extension in reversed(extensions):
#             frame = extension.decode(frame, max_size=max_size)
#
#         frame.check()
#
#         return frame
#
#     def serialize(
#         self,
#         *,
#         mask: bool,
#         extensions: Sequence[extensions.Extension] | None = None,
#     ) -> bytes:
#         """
#         Serialize a WebSocket frame.
#
#         Args:
#             mask: Whether the frame should be masked i.e. whether the write
#                 happens on the client side.
#             extensions: List of extensions, applied in order.
#
#         Raises:
#             ProtocolError: If the frame contains incorrect values.
#
#         """
#         self.check()
#
#         if extensions is None:
#             extensions = []
#         for extension in extensions:
#             self = extension.encode(self)
#
#         output = io.BytesIO()
#
#         # Prepare the header.
#         head1 = (
#             (0b10000000 if self.fin else 0)
#             | (0b01000000 if self.rsv1 else 0)
#             | (0b00100000 if self.rsv2 else 0)
#             | (0b00010000 if self.rsv3 else 0)
#             | self.opcode
#         )
#
#         head2 = 0b10000000 if mask else 0
#
#         length = len(self.data)
#         if length < 126:
#             output.write(struct.pack("!BB", head1, head2 | length))
#         elif length < 65536:
#             output.write(struct.pack("!BBH", head1, head2 | 126, length))
#         else:
#             output.write(struct.pack("!BBQ", head1, head2 | 127, length))
#
#         if mask:
#             mask_bytes = secrets.token_bytes(4)
#             output.write(mask_bytes)
#
#         # Prepare the data.
#         if mask:
#             data = apply_mask(self.data, mask_bytes)
#         else:
#             data = self.data
#         output.write(data)
#
#         return output.getvalue()
#
#     def check(self) -> None:
#         """
#         Check that reserved bits and opcode have acceptable values.
#
#         Raises:
#             ProtocolError: If a reserved bit or the opcode is invalid.
#
#         """
#         if self.rsv1 or self.rsv2 or self.rsv3:
#             raise ProtocolError("reserved bits must be 0")
#
#         if self.opcode in CTRL_OPCODES:
#             if len(self.data) > 125:
#                 raise ProtocolError("control frame too long")
#             if not self.fin:
#                 raise ProtocolError("fragmented control frame")
#
#
# @dataclasses.dataclass
# class Close:
#     """
#     Code and reason for WebSocket close frames.
#
#     Attributes:
#         code: Close code.
#         reason: Close reason.
#
#     """
#
#     code: int
#     reason: str
#
#     def __str__(self) -> str:
#         """
#         Return a human-readable representation of a close code and reason.
#
#         """
#         if 3000 <= self.code < 4000:
#             explanation = "registered"
#         elif 4000 <= self.code < 5000:
#             explanation = "private use"
#         else:
#             explanation = CLOSE_CODE_EXPLANATIONS.get(self.code, "unknown")
#         result = f"{self.code} ({explanation})"
#
#         if self.reason:
#             result = f"{result} {self.reason}"
#
#         return result
#
#     @classmethod
#     def parse(cls, data: bytes) -> Close:
#         """
#         Parse the payload of a close frame.
#
#         Args:
#             data: Payload of the close frame.
#
#         Raises:
#             ProtocolError: If data is ill-formed.
#             UnicodeDecodeError: If the reason isn't valid UTF-8.
#
#         """
#         if len(data) >= 2:
#             (code,) = struct.unpack("!H", data[:2])
#             reason = data[2:].decode()
#             close = cls(code, reason)
#             close.check()
#             return close
#         elif len(data) == 0:
#             return cls(CloseCode.NO_STATUS_RCVD, "")
#         else:
#             raise ProtocolError("close frame too short")
#
#     def serialize(self) -> bytes:
#         """
#         Serialize the payload of a close frame.
#
#         """
#         self.check()
#         return struct.pack("!H", self.code) + self.reason.encode()
#
#     def check(self) -> None:
#         """
#         Check that the close code has a valid value for a close frame.
#
#         Raises:
#             ProtocolError: If the close code is invalid.
#
#         """
#         if not (self.code in EXTERNAL_CLOSE_CODES or 3000 <= self.code < 5000):
#             raise ProtocolError("invalid status code")
#
#
# # At the bottom to break import cycles created by type annotations.
# from . import extensions  # noqa: E402
