from utils import Span


fn to_string[T: Formattable](value: T) -> String:
    var s = String()
    var formatter = s._unsafe_to_formatter()
    value.format_to(formatter)
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
