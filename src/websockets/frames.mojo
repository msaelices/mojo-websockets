from bit import byte_swap
from collections import Dict, Optional
from collections.string import StringSlice
from memory import bitcast, memcmp, UnsafePointer
from sys.info import is_big_endian

from websockets.streams import Streamable
from websockets.utils.string import Bytes, ByteWriter
from websockets.utils.bytes import pack, unpack, int_as_bytes, int_from_bytes, gen_mask


# Opcodes for WebSocket frames
struct OpCode:
    """
    Opcodes for WebSocket frames.
    """

    alias OP_CONT = 0x00
    alias OP_TEXT = 0x01
    alias OP_BINARY = 0x02
    alias OP_CLOSE = 0x08
    alias OP_PING = 0x09
    alias OP_PONG = 0x0A


alias DATA_OPCODES = (
    OpCode.OP_CONT,
    OpCode.OP_TEXT,
    OpCode.OP_BINARY,
)

alias CTRL_OPCODES = (
    OpCode.OP_CLOSE,
    OpCode.OP_PING,
    OpCode.OP_PONG,
)


# Close codes
struct CloseCode:
    """
    Close codes for WebSocket close frames.
    """

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
    CloseCode.CLOSE_CODE_NORMAL_CLOSURE,
    CloseCode.CLOSE_CODE_GOING_AWAY,
    CloseCode.CLOSE_CODE_PROTOCOL_ERROR,
    CloseCode.CLOSE_CODE_UNSUPPORTED_DATA,
    CloseCode.CLOSE_CODE_INVALID_DATA,
    CloseCode.CLOSE_CODE_POLICY_VIOLATION,
    CloseCode.CLOSE_CODE_MESSAGE_TOO_BIG,
    CloseCode.CLOSE_CODE_MANDATORY_EXTENSION,
    CloseCode.CLOSE_CODE_INTERNAL_ERROR,
    CloseCode.CLOSE_CODE_SERVICE_RESTART,
    CloseCode.CLOSE_CODE_TRY_AGAIN_LATER,
    CloseCode.CLOSE_CODE_BAD_GATEWAY,
)

# OK codes in a closed frame.
alias OK_CLOSE_CODES = (
    CloseCode.CLOSE_CODE_NORMAL_CLOSURE,
    CloseCode.CLOSE_CODE_GOING_AWAY,
    CloseCode.CLOSE_CODE_NO_STATUS_RCVD,
)

alias MAX_FRAME_OVERHEAD = 14  # FIN bit and opcode (1 byte) + length (1 or 3 or 9 bytes) + mask (4 bytes)


@always_inline
fn get_op_code_name(code: Int) raises -> String:
    var name: String
    if code == OpCode.OP_CONT:
        name = "CONT"
    elif code == OpCode.OP_TEXT:
        name = "TEXT"
    elif code == OpCode.OP_BINARY:
        name = "BINARY"
    elif code == OpCode.OP_CLOSE:
        name = "CLOSE"
    elif code == OpCode.OP_PING:
        name = "PING"
    elif code == OpCode.OP_PONG:
        name = "PONG"
    else:
        name = "UNKNOWN"
    return name


@always_inline
fn get_close_code_name(code: UInt16) raises -> String:
    var name: String
    if code == CloseCode.CLOSE_CODE_NORMAL_CLOSURE:
        name = "NORMAL_CLOSURE"
    elif code == CloseCode.CLOSE_CODE_GOING_AWAY:
        name = "GOING_AWAY"
    elif code == CloseCode.CLOSE_CODE_PROTOCOL_ERROR:
        name = "PROTOCOL_ERROR"
    elif code == CloseCode.CLOSE_CODE_UNSUPPORTED_DATA:
        name = "UNSUPPORTED_DATA"
    elif code == CloseCode.CLOSE_CODE_NO_STATUS_RCVD:
        name = "NO_STATUS_RCVD"
    elif code == CloseCode.CLOSE_CODE_ABNORMAL_CLOSURE:
        name = "ABNORMAL_CLOSURE"
    elif code == CloseCode.CLOSE_CODE_INVALID_DATA:
        name = "INVALID_DATA"
    elif code == CloseCode.CLOSE_CODE_POLICY_VIOLATION:
        name = "POLICY_VIOLATION"
    elif code == CloseCode.CLOSE_CODE_MESSAGE_TOO_BIG:
        name = "MESSAGE_TOO_BIG"
    elif code == CloseCode.CLOSE_CODE_MANDATORY_EXTENSION:
        name = "MANDATORY_EXTENSION"
    elif code == CloseCode.CLOSE_CODE_INTERNAL_ERROR:
        name = "INTERNAL_ERROR"
    elif code == CloseCode.CLOSE_CODE_SERVICE_RESTART:
        name = "SERVICE_RESTART"
    elif code == CloseCode.CLOSE_CODE_TRY_AGAIN_LATER:
        name = "TRY_AGAIN_LATER"
    elif code == CloseCode.CLOSE_CODE_BAD_GATEWAY:
        name = "BAD_GATEWAY"
    elif code == CloseCode.CLOSE_CODE_TLS_HANDSHAKE:
        name = "TLS_HANDSHAKE"
    else:
        name = "UNKNOWN"
    return name


@always_inline
fn get_close_code_explanation(code: UInt16) raises -> String:
    var explanation: String
    if code == CloseCode.CLOSE_CODE_NORMAL_CLOSURE:
        explanation = "OK"
    elif code == CloseCode.CLOSE_CODE_GOING_AWAY:
        explanation = "going away"
    elif code == CloseCode.CLOSE_CODE_PROTOCOL_ERROR:
        explanation = "protocol error"
    elif code == CloseCode.CLOSE_CODE_UNSUPPORTED_DATA:
        explanation = "unsupported data"
    elif code == CloseCode.CLOSE_CODE_NO_STATUS_RCVD:
        explanation = "no status received [internal]"
    elif code == CloseCode.CLOSE_CODE_ABNORMAL_CLOSURE:
        explanation = "abnormal closure [internal]"
    elif code == CloseCode.CLOSE_CODE_INVALID_DATA:
        explanation = "invalid frame payload data"
    elif code == CloseCode.CLOSE_CODE_POLICY_VIOLATION:
        explanation = "policy violation"
    elif code == CloseCode.CLOSE_CODE_MESSAGE_TOO_BIG:
        explanation = "message too big"
    elif code == CloseCode.CLOSE_CODE_MANDATORY_EXTENSION:
        explanation = "mandatory extension"
    elif code == CloseCode.CLOSE_CODE_INTERNAL_ERROR:
        explanation = "internal error"
    elif code == CloseCode.CLOSE_CODE_SERVICE_RESTART:
        explanation = "service restart"
    elif code == CloseCode.CLOSE_CODE_TRY_AGAIN_LATER:
        explanation = "try again later"
    elif code == CloseCode.CLOSE_CODE_BAD_GATEWAY:
        explanation = "bad gateway"
    elif code == CloseCode.CLOSE_CODE_TLS_HANDSHAKE:
        explanation = "TLS handshake failure [internal]"
    else:
        explanation = "unknown"
    return explanation


fn apply_mask(data: Bytes, mask: Bytes) raises -> Bytes:
    """
    Apply masking to the data of a WebSocket message.

    Args:
        data: Data to mask.
        mask: 4-bytes mask.

    """
    if len(mask) != 4:
        raise Error(
            "ValueError: mask must contain 4 bytes and not " + String(len(mask))
        )

    # TODO: Use SIMD instructions to apply the mask.
    mask_repeated = mask * (len(data) // 4) + mask[: len(data) % 4]
    masked = Bytes(capacity=len(data))
    for i in range(len(data)):
        masked.append(Byte(data[i] ^ mask_repeated[i]))
    return masked


@value
struct Frame(Stringable, EqualityComparable):
    """
    WebSocket frame.

    Attributes:
        opcode: Int.
        data: Payload data.
        fin: FIN bit.
        rsv1: RSV1 bit.
        rsv2: RSV2 bit.
        rsv3: RSV3 bit.

    Only these fields are needed. The MASK bit, payload length and masking-key
    are handled on the fly when parsing and serializing frames.
    """

    var opcode: Int
    var data: Bytes
    var fin: Bool
    var rsv1: Bool
    var rsv2: Bool
    var rsv3: Bool

    fn __init__(out self, opcode: Int, data: Bytes, fin: Bool = True):
        self.opcode = opcode
        self.data = data
        self.fin = fin
        # reserved flags not used in the current websockets protocol
        self.rsv1 = False
        self.rsv2 = False
        self.rsv3 = False

    fn __eq__(self, other: Frame) -> Bool:
        var meta_is_eq = (
            self.opcode == other.opcode
            and self.fin == other.fin
            and self.rsv1 == other.rsv1
            and self.rsv2 == other.rsv2
            and self.rsv3 == other.rsv3
            and len(self.data) == len(other.data)
        )
        # TODO: Figure out why the single self.data == other.data comparison doesn't work
        # so we need to do this hack with memcmp
        return (
            meta_is_eq
            and memcmp(
                self.data.data, other.data.data, min(len(self.data), len(other.data))
            )
            == 0
        )

    fn __ne__(self, other: Frame) -> Bool:
        return not (self == other)

    fn __str__(self) -> String:
        var s = String()
        try:
            self.write_repr_to(s)
        except:
            s = "ERROR representing frame"
        return s

    # ===-------------------------------------------------------------------=== #
    # Methods
    # ===-------------------------------------------------------------------=== #

    fn write_repr_to[W: Writer](self, mut writer: W) raises:
        """
        Return a human-readable representation of a frame.

        Parameters:
            W: Writer type of the writer.

        Args:
            writer: Writer to write the representation to.
        """
        var coding: String = ""
        var data: String

        length = (
            String(Int(len(self.data))) + " byte" + ("" if len(self.data) == 1 else "s")
        )
        non_final = "" if self.fin else "continued"

        if self.opcode == OpCode.OP_TEXT:
            # Decoding only the beginning and the end is needlessly hard.
            # Decode the entire payload then elide later if necessary.
            data = self._data_as_text()
            coding = "text"
        elif self.opcode == OpCode.OP_BINARY:
            # We'll show at most the first 16 bytes and the last 8 bytes.
            # Encode just what we need, plus two dummy bytes to elide later.
            data = self._data_as_binary()
            coding = "binary"
        elif self.opcode == OpCode.OP_CLOSE:
            data = String(Close.parse(self.data))
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

        metadata = coding + ", " + length + ", " + non_final

        repr_data = "'" + data + "'" if coding == "text" else data
        writer.write(get_op_code_name(self.opcode), " ", repr_data, " [", metadata, "]")

    @always_inline
    fn _data_as_text(self) -> String:
        """
        Return the data as a string.
        """
        return String(
            StringSlice[__origin_of(self)](
                ptr=self.data.unsafe_ptr(), length=len(self.data)
            )
        )

    @always_inline
    fn _data_as_binary(self) raises -> String:
        """
        Return the data as a string.
        """
        var s: String = ""
        for byte in self.data:
            s += hex(byte) + " "
        return String(s.strip())

    fn check(self) raises -> None:
        """
        Check that reserved bits and opcode have acceptable values.

        Raises:
            ProtocolError: If a reserved bit or the opcode is invalid.

        """
        if self.rsv1 or self.rsv2 or self.rsv3:
            raise Error("ProtocolError: reserved bits must be 0")

        if self.opcode in CTRL_OPCODES:
            if len(self.data) > 125:
                raise Error("ProtocolError: control frame too long")
            if not self.fin:
                raise Error("ProtocolError: fragmented control frame")

    @always_inline
    fn is_data(self) -> Bool:
        """
        Return whether the frame is a data frame.

        """
        return self.opcode in DATA_OPCODES

    fn serialize[
        gen_mask_func: fn () -> Bytes = gen_mask,
    ](self, *, mask: Bool,) raises -> Bytes:
        """
        Serialize a WebSocket frame.

        Args:
            mask: Whether the frame should be masked i.e. whether the write
                happens on the client side.

        Raises:
            ProtocolError: If the frame contains incorrect values.

        Returns:
            The serialized frame.
        """
        self.check()

        length = len(self.data)
        output = ByteWriter(capacity=length + MAX_FRAME_OVERHEAD)

        # Prepare the header.
        head1 = (
            (0b10000000 if self.fin else 0)
            | (0b01000000 if self.rsv1 else 0)
            | (0b00100000 if self.rsv2 else 0)
            | (0b00010000 if self.rsv3 else 0)
            | self.opcode
        )
        head2 = 0b10000000 if mask else 0

        if length < 126:
            output.write_bytes(pack["!BB"](head1, head2 | length))
        elif length < 65536:
            output.write_bytes(pack["!BBH"](head1, head2 | 126, length))
        else:
            output.write_bytes(pack["!BBQ"](head1, head2 | 127, length))

        if mask:
            mask_bytes = gen_mask_func()
            output.write_bytes(mask_bytes)
            data = apply_mask(self.data, mask_bytes)
        else:
            data = self.data
        output.write_bytes(data)

        return output.consume()

    @staticmethod
    fn parse[
        T: Streamable
    ](stream_ptr: UnsafePointer[T], *, mask: Bool,) raises -> Optional[Frame]:
        """
        Parse a WebSocket frame.

        This is a generator-based coroutine.

        Args:
            stream_ptr: Unsafe pointer to the stream to read from.
            mask: Whether the frame should be masked i.e. whether the read
                happens on the server side.

        Returns:
            The parsed frame.

        Raises:
            EOFError: If the connection is closed without a full WebSocket frame.
            UnicodeDecodeError: If the frame contains invalid UTF-8.
            PayloadTooBig: If the frame's payload size exceeds ``max_size``.
            ProtocolError: If the frame contains incorrect values.

        """
        # Read the header.
        data_or_none = stream_ptr[].read_exact(2)
        if data_or_none is None:
            # Return waiting for more data to be available
            return None
        data = data_or_none.value()
        unpacked_data = unpack("!BB", data)

        head1 = unpacked_data[0]
        head2 = unpacked_data[1]

        # Convert bit flags to boolean values
        fin = head1 & 0b10000000 != 0
        rsv1 = head1 & 0b01000000 != 0
        rsv2 = head1 & 0b00100000 != 0
        rsv3 = head1 & 0b00010000 != 0

        opcode = Int(head1 & 0b00001111)

        if opcode not in DATA_OPCODES and opcode not in CTRL_OPCODES:
            raise Error("ProtocolError: invalid opcode: " + String(opcode))

        # Check if the mask bit is set correctly.
        if (head2 & 0b10000000 != 0) != mask:
            raise Error("ProtocolError: incorrect masking")

        length = head2 & 0b01111111
        if length == 126:
            data = stream_ptr[].read_exact(2).value()
            length = unpack("!H", data)[0]
        elif length == 127:
            data = stream_ptr[].read_exact(8).value()
            length = unpack("!Q", data)[0]
        if mask:
            mask_bytes = stream_ptr[].read_exact(4).value()
            data = stream_ptr[].read_exact(length).value()
            if mask:
                data = apply_mask(data, mask_bytes)
        else:
            data = stream_ptr[].read_exact(length).value()

        frame = Frame(opcode, data, fin, rsv1, rsv2, rsv3)
        frame.check()

        return frame


@value
struct Close(StringableRaising):
    """
    Code and reason for WebSocket close frames.

    Attributes:
        code: Close code.
        reason: Close reason.
    """

    var code: UInt16
    var reason: String

    fn __str__(self) raises -> String:
        """
        Return a human-readable representation of a close code and reason.

        """
        var explanation: String
        if UInt16(3000) <= self.code < UInt16(4000):
            explanation = "registered"
        elif UInt16(4000) <= self.code < UInt16(5000):
            explanation = "private use"
        else:
            explanation = get_close_code_explanation(self.code)
        result = get_close_code_name(self.code) + " (" + explanation + ")"

        if self.reason:
            result = result + " " + self.reason

        return result

    @staticmethod
    fn parse(data: Bytes) raises -> Close:
        """
        Parse the payload of a close frame.

        Args:
            data: Payload of the close frame.

        Raises:
            ProtocolError: If data is ill-formed.
        """
        if len(data) >= 2:
            # This is equivalent to struct.unpack("!H", data[:2])
            data_u16 = data.unsafe_ptr().bitcast[UInt16]()[]

            @parameter
            if not is_big_endian():
                code = Int(byte_swap(data_u16))
            else:
                code = Int(data_u16)
            reason = String(
                StringSlice[__origin_of(data)](
                    ptr=data.unsafe_ptr().offset(2), length=len(data) - 2
                )
            )
            close = Close(code, reason)
            close.check()
            return close
        elif len(data) == 0:
            return Close(CloseCode.CLOSE_CODE_NO_STATUS_RCVD, "")
        else:
            raise Error("ProtocolError: close frame too short")

    fn serialize(self) raises -> Bytes:
        """
        Serialize the payload of a close frame.

        """
        self.check()

        # TODO: Check if this is equivalent to struct.pack("!H", self.code) + self.reason.encode()
        @parameter
        if not is_big_endian():
            code = byte_swap(self.code)
        else:
            code = self.code

        bytes = UnsafePointer(to=code).bitcast[Byte]()
        code_bytes = Bytes(bytes[0], bytes[1])
        code_bytes.extend(self.reason.as_bytes())
        return code_bytes

    fn check(self) raises -> None:
        """
        Check that the close code has a valid value for a close frame.

        Raises:
            Error: If the close code is invalid.

        """
        code = Int(self.code)
        if not (code in EXTERNAL_CLOSE_CODES or 3000 <= code < 5000):
            raise Error("ProtocolError: invalid status code: " + String(self.code))
