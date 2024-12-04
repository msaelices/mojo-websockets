"""
This module mimic the Python struct one converting between Mojo Butes and C structs

Compact format strings describe the intended conversions to/from Python values.
The module’s functions and objects can be used for two largely distinct applications, 
data exchange with external sources (files or network connections), or data transfer 
between the Python application and the C layer.
"""
from bit import byte_swap
from sys import bitwidthof
from sys.info import is_big_endian
from memory import bitcast, memcpy, UnsafePointer
from utils import Span, StringRef

from ..aliases import Bytes

alias MODIFIERS = List[String]('>', '<', '!', '=')
alias EOL = Byte(10)


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
    var order: String = '>' if is_big_endian() else '<'
    if len(format) > 1:
        if format[0] in MODIFIERS:
            # big-endian, little-endian, network, native
            offset = 1
            order = format[0]
    var fmt_span = format.as_bytes()[offset:]
    for c_ref in fmt_span:
        c = c_ref[]
        if c == ord('b'):
            values.append(int(reader.read[DType.int8](order)))
        elif c == ord('B'):
            values.append(int(reader.read[DType.uint8](order)))
        elif c == ord('h'):
            values.append(int(reader.read[DType.int16](order)))
        elif c == ord('H'):
            values.append(int(reader.read[DType.uint16](order)))
        elif c == ord('i'):
            values.append(int(reader.read[DType.int32](order)))
        elif c == ord('I'):
            values.append(int(reader.read[DType.uint32](order)))
        elif c == ord('l'):
            values.append(int(reader.read[DType.int32](order)))
        elif c == ord('L'):
            values.append(int(reader.read[DType.uint32](order)))
        elif c == ord('q'):
            values.append(int(reader.read[DType.int64](order)))
        elif c == ord('Q'):
            values.append(int(reader.read[DType.uint64](order)))
        else:
            raise Error("ValueError: Unknown format character: {}".format(String(c)))
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
    alias order: String = '>' if is_big_endian() else '<'
    var offset = 0

    @parameter
    if len(format) > 1 and format[0] in MODIFIERS:
        # big-endian, little-endian, network, native
        offset = 1

    var fmt_span = format.as_bytes()[offset:]
    var i = 0
    alias big_endian = format[0] == '>' or format[0] == '!' or is_big_endian()

    var buffer = Bytes(capacity=len(fmt_span) * 8)  # 8 is the maximum size of a type
    for c_ref in fmt_span:
        c = c_ref[]
        if c == ord('b'):
            buffer += int_as_bytes[DType.int8, big_endian](values[i])
        elif c == ord('B'):
            buffer += int_as_bytes[DType.uint8, big_endian](values[i])
        elif c == ord('h'):
            buffer += int_as_bytes[DType.int16, big_endian](values[i])
        elif c == ord('H'):
            buffer += int_as_bytes[DType.uint16, big_endian](values[i])
        elif c == ord('i'):
            buffer += int_as_bytes[DType.int32, big_endian](values[i])
        elif c == ord('I'):
            buffer += int_as_bytes[DType.uint32, big_endian](values[i])
        elif c == ord('l'):
            buffer += int_as_bytes[DType.int32, big_endian](values[i])
        elif c == ord('L'):
            buffer += int_as_bytes[DType.uint32, big_endian](values[i])
        elif c == ord('q'):
            buffer += int_as_bytes[DType.int64, big_endian](values[i])
        elif c == ord('Q'):
            buffer += int_as_bytes[DType.uint64, big_endian](values[i])
        else:
            raise Error("ValueError: Unknown format character: {}".format(String(c)))
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
        self.buffer = Pointer[Bytes, ImmutableAnyOrigin].address_of(buffer)
        self.index = 0

    fn read[type: DType](inout self, order: String) raises -> Scalar[type]:
        """
        Read the next value from the buffer.

        Args:
            order: The order of the bytes in the buffer.

        Returns:
            The next value from the buffer.
        """
        return self._next[type](order)

    fn _next[type: DType](inout self, order: String) raises -> Scalar[type]:
        """
        Read the next value from the buffer.

        Args:
            order: The order of the bytes in the buffer.

        Returns:
            The next value from the buffer.
        """
        var ptr: UnsafePointer[Byte] = UnsafePointer.address_of(self.buffer[][self.index])
        alias width = bitwidthof[type]() 
        var value: SIMD[type, 1] = ptr.bitcast[Scalar[type]]()[]
        var ordered_value = self._set_order(value, order)
        self.index += width // 8
        return ordered_value

    fn _set_order[type: DType, //](self, value: SIMD[type, 1], order: String) raises -> Scalar[type]:
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
            if order == '>' or order == '!':
                ordered = byte_swap(value)
        else:
            if order == '<':
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
    if type.sizeof() != len(bytes):
        raise Error("Byte array size does not match the integer size.")
    var ptr: UnsafePointer[Byte] = UnsafePointer.address_of(bytes[0])
    var type_ptr: UnsafePointer[Scalar[type]] = ptr.bitcast[Scalar[type]]()
    var value = type_ptr[]

    @parameter
    if is_big_endian() and not big_endian:
        value = byte_swap(value)
    elif not is_big_endian() and big_endian:
        value = byte_swap(value)
    return int(value)


fn int_as_bytes[
    type: DType, big_endian: Bool = False
](value: Scalar[type]) -> Bytes:
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
    if is_big_endian() and not big_endian:
        ordered_value = byte_swap(value)
    elif not is_big_endian() and big_endian:
        ordered_value = byte_swap(value)
    else:
        ordered_value = value

    var ptr: UnsafePointer[Scalar[type]] = UnsafePointer.address_of(ordered_value)
    var byte_ptr: UnsafePointer[Byte] = ptr.bitcast[Byte]()
    var list = Bytes(capacity=type_len)

    memcpy(list.unsafe_ptr(), byte_ptr, type_len)
    list.size = type_len

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
    for c in s:
        bytes.append(ord(c))
    return bytes
