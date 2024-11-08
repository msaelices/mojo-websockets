"""
This module mimic the Python struct one converting between Mojo Butes and C structs

Compact format strings describe the intended conversions to/from Python values.
The module’s functions and objects can be used for two largely distinct applications, 
data exchange with external sources (files or network connections), or data transfer 
between the Python application and the C layer.
"""
from sys.info import is_big_endian
from memory import bitcast
from utils import StringRef

from ..aliases import Bytes

alias MODIFIERS = List[String]('>', '<', '!', '=')


fn unpack(format: String, buffer: Bytes) raises -> List[Int]:
    """Unpack the buffer according to the format string.

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
            values.append(reader.read_byte(order))
        elif c == ord('B'):
            values.append(reader.read_ubyte(order))
        # elif c == ord('h'):
        #     values.append(reader.read_short())
        # elif c == ord('i'):
        #     values.append(reader.read_int())
        # elif c == ord('q'):
        #     values.append(reader.read_long())
        # elif c == ord('H'):
        #     values.append(reader.read_ushort())
        # elif c == ord('I'):
        #     values.append(reader.read_uint())
        # elif c == ord('Q'):
        #     values.append(reader.read_ulong())
        # elif c == ord('f'):
        #     values.append(reader.read_float())
        # elif c == ord('d'):
        #     values.append(reader.read_double())
        # elif c == ord('s'):
        #     values.append(reader.read_string())
        # elif c == ord('S'):
        #     values.append(reader.read_bytes())
        else:
            raise Error("ValueError: Unknown format character: {}".format(String(c)))
    return values


@value
struct ByteReader:
    var buffer: Pointer[Bytes, ImmutableAnyOrigin]
    var index: Int

    fn __init__(inout self, buffer: Bytes):
        self.buffer = Pointer[Bytes, ImmutableAnyOrigin].address_of(buffer)
        self.index = 0

    fn read_byte(inout self, order: String) -> Int:
        var value = bitcast[DType.int8](self.buffer[][self.index])
        self.index += 1
        return int(value)

    fn read_ubyte(inout self, order: String) -> Int:
        var value = self.buffer[][self.index]
        self.index += 1
        return int(value)
