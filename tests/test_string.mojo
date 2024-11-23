import testing
from collections import Dict, List

from websockets.aliases import Bytes
from websockets.utils.string import bytes_equal, bytes


def test_io():
    test_string_literal_to_bytes()


fn test_string_literal_to_bytes() raises:
    var cases = Dict[StringLiteral, Bytes]()
    cases[""] = Bytes()
    cases["Hello world!"] = Bytes(
        72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 33
    )
    cases["\0"] = Bytes(0)
    cases["\0\0\0\0"] = Bytes(0, 0, 0, 0)
    cases["OK"] = Bytes(79, 75)
    cases["HTTP/1.1 200 OK"] = Bytes(
        72, 84, 84, 80, 47, 49, 46, 49, 32, 50, 48, 48, 32, 79, 75
    )

    for c in cases.items():
        testing.assert_true(bytes_equal(bytes(c[].key), c[].value))


fn test_string_to_bytes() raises:
    var cases = Dict[String, Bytes]()
    cases[String("")] = Bytes()
    cases[String("Hello world!")] = Bytes(
        72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 33
    )
    cases[String("\0")] = Bytes(0)
    cases[String("\0\0\0\0")] = Bytes(0, 0, 0, 0)
    cases[String("OK")] = Bytes(79, 75)
    cases[String("HTTP/1.1 200 OK")] = Bytes(
        72, 84, 84, 80, 47, 49, 46, 49, 32, 50, 48, 48, 32, 79, 75
    )

    for c in cases.items():
        testing.assert_true(bytes_equal(bytes(c[].key), c[].value))
