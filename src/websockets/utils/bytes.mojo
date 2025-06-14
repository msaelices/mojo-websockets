"""
This module mimic the Python struct one converting between Mojo Butes and C structs

Compact format strings describe the intended conversions to/from Python values.
The module’s functions and objects can be used for two largely distinct applications,
data exchange with external sources (files or network connections), or data transfer
between the Python application and the C layer.
"""
from bit import byte_swap
from collections.string import StringSlice
from sys import bitwidthof
from sys.info import is_big_endian
from memory import bitcast, memcpy, Span, UnsafePointer
from random import randint

from websockets.aliases import Bytes

alias MODIFIERS = List[String](">", "<", "!", "=")
alias EOL = Byte(10)


@always_inline
fn byte(s: String) -> Byte:
    return ord(s)


@always_inline
fn bytes(s: String) -> Bytes:
    return Bytes(s.as_bytes())


fn unpack(format: String, buffer: Bytes) raises -> List[Int]:
    """Unpack the buffer according to the format string.

    See https://docs.python.org/3/library/struct.html for more information.

    Supported formats:
    - b: int8
    - B: uint8
    - h: int16
    - H: uint16
    - i: int32
    - I: uint32
    - l: int32
    - L: uint32
    - q: int64
    - Q: uint64

    Unsupported formats: b, B, s, S, f, F, because of they do not return integers.

    Args:
        format: The format string.
        buffer: The buffer to unpack.

    Returns:
        The unpacked values.
    """
    var reader = ByteReader(buffer)
    var values = List[Int]()
    var offset = 0
    var order: String = ">" if is_big_endian() else "<"
    if len(format) > 1:
        if format[0] in MODIFIERS:
            # big-endian, little-endian, network, native
            offset = 1
            order = format[0]
    var fmt_span = format.as_bytes()[offset:]
    for c in fmt_span:
        if c == ord("b"):
            values.append(Int(reader.read[DType.int8](order)))
        elif c == ord("B"):
            values.append(Int(reader.read[DType.uint8](order)))
        elif c == ord("h"):
            values.append(Int(reader.read[DType.int16](order)))
        elif c == ord("H"):
            values.append(Int(reader.read[DType.uint16](order)))
        elif c == ord("i"):
            values.append(Int(reader.read[DType.int32](order)))
        elif c == ord("I"):
            values.append(Int(reader.read[DType.uint32](order)))
        elif c == ord("l"):
            values.append(Int(reader.read[DType.int32](order)))
        elif c == ord("L"):
            values.append(Int(reader.read[DType.uint32](order)))
        elif c == ord("q"):
            values.append(Int(reader.read[DType.int64](order)))
        elif c == ord("Q"):
            values.append(Int(reader.read[DType.uint64](order)))
        else:
            raise Error("ValueError: Unknown format character: " + String(c))
    return values


fn pack[format: String](*values: Int) raises -> Bytes:
    """Pack the values according to the format string.

    See https://docs.python.org/3/library/struct.html for more information.

    Supported formats:
    - b: int8
    - B: uint8
    - h: int16
    - H: uint16
    - i: int32
    - I: uint32
    - l: int32
    - L: uint32
    - q: int64
    - Q: uint64

    Unsupported formats: b, B, s, S, f, F, because of they do not return integers.

    Parameters:
        format: The format string.

    Args:
        values: The values to pack.

    Returns:
        The packed buffer.
    """
    alias order: String = ">" if is_big_endian() else "<"
    var offset = 0

    @parameter
    if len(format) > 1 and format[0] in MODIFIERS:
        # big-endian, little-endian, network, native
        offset = 1

    var fmt_span = format[offset:]
    var i = 0
    alias big_endian = format[0] == ">" or format[0] == "!" or is_big_endian()

    var buffer = Bytes(capacity=len(fmt_span) * 8)  # 8 is the maximum size of a type
    for c in fmt_span.codepoint_slices():
        if c == "b":
            buffer += int_as_bytes[DType.int8, big_endian](values[i])
        elif c == "B":
            buffer += int_as_bytes[DType.uint8, big_endian](values[i])
        elif c == "h":
            buffer += int_as_bytes[DType.int16, big_endian](values[i])
        elif c == "H":
            buffer += int_as_bytes[DType.uint16, big_endian](values[i])
        elif c == "i":
            buffer += int_as_bytes[DType.int32, big_endian](values[i])
        elif c == "I":
            buffer += int_as_bytes[DType.uint32, big_endian](values[i])
        elif c == "l":
            buffer += int_as_bytes[DType.int32, big_endian](values[i])
        elif c == "L":
            buffer += int_as_bytes[DType.uint32, big_endian](values[i])
        elif c == "q":
            buffer += int_as_bytes[DType.int64, big_endian](values[i])
        elif c == "Q":
            buffer += int_as_bytes[DType.uint64, big_endian](values[i])
        else:
            raise Error("ValueError: Unknown format character: " + String(c))
        i += 1
    return buffer


@value
struct ByteReader:
    var buffer: Pointer[Bytes, ImmutableAnyOrigin]
    """The buffer to read from."""
    var index: Int
    """The current index in the buffer."""

    fn __init__(out self, buffer: Bytes):
        """
        Initialize the ByteReader.

        Args:
            buffer: The buffer to read from.
        """
        self.buffer = Pointer[Bytes, ImmutableAnyOrigin](to=buffer)
        self.index = 0

    fn read[type: DType](mut self, order: String) raises -> Scalar[type]:
        """
        Read the next value from the buffer.

        Args:
            order: The order of the bytes in the buffer.

        Returns:
            The next value from the buffer.
        """
        return self._next[type](order)

    fn _next[type: DType](mut self, order: String) raises -> Scalar[type]:
        """
        Read the next value from the buffer.

        Args:
            order: The order of the bytes in the buffer.

        Returns:
            The next value from the buffer.
        """
        var ptr: UnsafePointer[Byte] = UnsafePointer(to=self.buffer[][self.index])
        alias width = bitwidthof[type]()
        var value: SIMD[type, 1] = ptr.bitcast[Scalar[type]]()[]
        var ordered_value = self._set_order(value, order)
        self.index += width // 8
        return ordered_value

    fn _set_order[
        type: DType, //
    ](self, value: SIMD[type, 1], order: String) raises -> Scalar[type]:
        """
        Set the order of the bytes in the value.

        Args:
            value: The value to set the order.
            order: The order of the bytes in the value.

        Returns:
            The value with the order set.
        """
        var ordered: Scalar[type] = value
        alias width = bitwidthof[type]()

        @parameter
        if width == 8:
            return ordered

        @parameter
        if not is_big_endian():
            if order == ">" or order == "!":
                ordered = byte_swap(value)
        else:
            if order == "<":
                ordered = byte_swap(value)
        return ordered


# TODO: Remove this function if the https://github.com/modularml/mojo/pull/3795 is merged
fn int_from_bytes[
    type: DType, big_endian: Bool = False
](bytes: Span[Byte]) raises -> Int:
    """Converts a byte array to an integer.

    Args:
        bytes: The byte array to convert.

    Parameters:
        type: The type of the integer.
        big_endian: Whether the byte array is big-endian.

    Returns:
        The integer value.
    """
    if len(bytes) % type.sizeof() != 0:
        raise Error("Byte array size is not a multiple of the integer size.")
    var ptr: UnsafePointer[Byte] = UnsafePointer(to=bytes[0])
    var type_ptr: UnsafePointer[Scalar[type]] = ptr.bitcast[Scalar[type]]()
    var value = type_ptr[]

    @parameter
    if is_big_endian() and not big_endian:
        value = byte_swap(value)
    elif not is_big_endian() and big_endian:
        value = byte_swap(value)
    return Int(value)


fn int_as_bytes[type: DType, big_endian: Bool = False](value: Scalar[type]) -> Bytes:
    """Convert the integer to a byte array.
    Parameters:
        type: The type of the integer.
        big_endian: Whether the byte array should be big-endian.
    Returns:
        The byte array.
    """
    alias type_len = type.sizeof()
    var ordered_value: Scalar[type]

    @parameter
    if type_len % 2 == 0 and is_big_endian() and not big_endian:
        ordered_value = byte_swap(value)
    elif type_len % 2 == 0 and not is_big_endian() and big_endian:
        ordered_value = byte_swap(value)
    else:
        ordered_value = value

    var ptr: UnsafePointer[Scalar[type]] = UnsafePointer(to=ordered_value)
    var byte_ptr: UnsafePointer[Byte] = ptr.bitcast[Byte]()
    var list = Bytes(capacity=type_len)

    memcpy(list.unsafe_ptr(), byte_ptr, type_len)
    list._len = type_len

    return list^


fn str_to_bytes(s: String) -> Bytes:
    """Convert a string to a byte array.

    Args:
        s: The string to convert.

    Returns:
        The byte array.
    """
    capacity = len(s)
    bytes = Bytes(capacity=capacity)
    for c in s.codepoint_slices():
        bytes.append(ord(c))
    return bytes


fn bytes_to_str(bytes: Bytes) -> String:
    """Convert a byte array to a string.

    Args:
        bytes: The byte array to convert.

    Returns:
        The string.
    """
    return String(
        StringSlice[__origin_of(bytes)](ptr=bytes.unsafe_ptr(), length=len(bytes))
    )


@always_inline
fn gen_token(length: Int) -> Bytes:
    """
    Generate a random token.
    """
    token = Bytes(capacity=length)
    token._len = length
    randint[Byte.type](token.unsafe_ptr(), length, 0, 255)
    return token^


@always_inline
fn gen_mask() -> Bytes:
    """
    Generate a random mask.
    """
    mask = gen_token(4)
    return mask^


# TODO: Remove this function when the validate parameter is implemented in the Mojo base64 module
# See https://github.com/modularml/mojo/pull/3929
@always_inline
fn b64decode[validate: Bool = False](str: String) raises -> String:
    """Performs base64 decoding on the input string.

    Parameters:
      validate: If true, the function will validate the input string.

    Args:
      str: A base64 encoded string.

    Returns:
      The decoded string.
    """
    var n = str.byte_length()

    @parameter
    if validate:
        if n % 4 != 0:
            raise Error("ValueError: Input length must be divisible by 4")

    var p = Bytes(capacity=n + 1)

    # This algorithm is based on https://arxiv.org/abs/1704.00605
    for i in range(0, n, 4):
        var a = _ascii_to_value(str[i])
        var b = _ascii_to_value(str[i + 1])
        var c = _ascii_to_value(str[i + 2])
        var d = _ascii_to_value(str[i + 3])

        @parameter
        if validate:
            if a < 0 or b < 0 or c < 0 or d < 0:
                raise Error("ValueError: Unexpected character encountered")

        p.append((a << 2) | (b >> 4))
        if str[i + 2] == "=":
            break

        p.append(((b & 0x0F) << 4) | (c >> 2))

        if str[i + 3] == "=":
            break

        p.append(((c & 0x03) << 6) | d)

    p.append(0)
    # Use StringSlice for conversion in Max 25.3
    p.append(0)
    return String(StringSlice(ptr=p.data, length=len(p) - 1))


@always_inline
fn _ascii_to_value(char_value: String) -> Int:
    """Converts an ASCII character to its integer value for base64 decoding.

    Args:
        char_value: A single character string.

    Returns:
        The integer value of the character for base64 decoding, or -1 if invalid.
    """
    var char_val = ord(char_value)

    if char_value == "=":
        return 0
    elif ord("A") <= char_val <= ord("Z"):
        return char_val - ord("A")
    elif ord("a") <= char_val <= ord("z"):
        return char_val - ord("a") + 26
    elif ord("0") <= char_val <= ord("9"):
        return char_val - ord("0") + 52
    elif char_value == "+":
        return 62
    elif char_value == "/":
        return 63
    else:
        return -1


@always_inline
fn bytes_equal(a: Bytes, b: Bytes) -> Bool:
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True
