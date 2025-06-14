from collections import List, Dict
from sys.info import is_big_endian
from testing import assert_equal, assert_true, assert_false

from websockets.aliases import Bytes
from websockets.utils import bytes
from testutils import assert_bytes_equal


fn test_unpack() raises:
    # Test some of the unpack features in detail
    # (format, argument, big-endian result, little-endian result)
    var tests = [
        (
            String("b"),
            List(
                7,
            ),
            Bytes(7),
            Bytes(7),
        ),
        (
            String("b"),
            List(
                -7,
            ),
            Bytes(249),
            Bytes(249),
        ),
        (
            String("B"),
            List(
                7,
            ),
            Bytes(7),
            Bytes(7),
        ),
        (
            String("B"),
            List(
                249,
            ),
            Bytes(249),
            Bytes(249),
        ),
        (
            String("h"),
            List(
                700,
            ),
            Bytes(2, 188),
            Bytes(188, 2),
        ),
        (
            String("h"),
            List(
                -700,
            ),
            Bytes(253, 68),
            Bytes(68, 253),
        ),
        (String("hh"), List(258, 772), Bytes(1, 2, 3, 4), Bytes(2, 1, 4, 3)),
        (
            String("H"),
            List(
                700,
            ),
            Bytes(2, 188),
            Bytes(188, 2),
        ),
        (
            String("H"),
            List(
                0x10000 - 700,
            ),
            Bytes(253, 68),
            Bytes(68, 253),
        ),
        (
            String("i"),
            List(
                1,
            ),
            Bytes(0, 0, 0, 1),
            Bytes(1, 0, 0, 0),
        ),
        (
            String("i"),
            List(
                -1,
            ),
            Bytes(255, 255, 255, 255),
            Bytes(255, 255, 255, 255),
        ),
        (
            String("i"),
            List(
                70006144,
            ),
            Bytes(4, 44, 53, 128),
            Bytes(128, 53, 44, 4),
        ),
        (
            String("ii"),
            List(16909060, 84281096),
            Bytes(1, 2, 3, 4, 5, 6, 7, 8),
            Bytes(4, 3, 2, 1, 8, 7, 6, 5),
        ),
        (
            String("I"),
            List(
                1,
            ),
            Bytes(0, 0, 0, 1),
            Bytes(1, 0, 0, 0),
        ),
        (
            String("I"),
            List(
                4294967295,
            ),
            Bytes(255, 255, 255, 255),
            Bytes(255, 255, 255, 255),
        ),
        (
            String("q"),
            List(
                283686952306183,
            ),
            Bytes(0, 1, 2, 3, 4, 5, 6, 7),
            Bytes(7, 6, 5, 4, 3, 2, 1, 0),
        ),
        (
            String("i"),
            List(
                70000000,
            ),
            Bytes(4, 44, 29, 128),
            Bytes(128, 29, 44, 4),
        ),
        (
            String("i"),
            List(
                -70000000,
            ),
            Bytes(251, 211, 226, 128),
            Bytes(128, 226, 211, 251),
        ),
        (
            String("I"),
            List(
                70000000,
            ),
            Bytes(4, 44, 29, 128),
            Bytes(128, 29, 44, 4),
        ),
        (
            String("I"),
            List(
                0x100000000 - 70000000,
            ),
            Bytes(251, 211, 226, 128),
            Bytes(128, 226, 211, 251),
        ),
        (
            String("l"),
            List(
                70000000,
            ),
            Bytes(4, 44, 29, 128),
            Bytes(128, 29, 44, 4),
        ),
        (
            String("l"),
            List(
                -70000000,
            ),
            Bytes(251, 211, 226, 128),
            Bytes(128, 226, 211, 251),
        ),
        (
            String("L"),
            List(
                70000000,
            ),
            Bytes(4, 44, 29, 128),
            Bytes(128, 29, 44, 4),
        ),
        (
            String("L"),
            List(
                0x100000000 - 70000000,
            ),
            Bytes(251, 211, 226, 128),
            Bytes(128, 226, 211, 251),
        ),
    ]
    var i: Int

    for test in tests:
        fmt, args, big, lil = test
        for op in [
            (String(">{}").format(fmt), big),
            (String("!{}").format(fmt), big),
            (String("<{}").format(fmt), lil),
            (String("={}").format(fmt), big if is_big_endian() else lil),
        ]:
            xfmt, exp = op
            values = bytes.unpack(xfmt, exp)
            i = 0
            assert_equal(len(values), len(args))
            for value in values:
                assert_equal(
                    args[i],
                    value,
                )
                i += 1


fn test_pack() raises:
    assert_bytes_equal(bytes.pack["b"](7), Bytes(7))
    assert_bytes_equal(bytes.pack["b"](-7), Bytes(249))
    assert_bytes_equal(bytes.pack["B"](7), Bytes(7))
    assert_bytes_equal(bytes.pack["B"](249), Bytes(249))
    assert_bytes_equal(bytes.pack["!B"](7), Bytes(7))
    assert_bytes_equal(bytes.pack["h"](700), Bytes(188, 2))
    assert_bytes_equal(bytes.pack["H"](700), Bytes(188, 2))
    assert_bytes_equal(bytes.pack["h"](-700), Bytes(68, 253))
    assert_bytes_equal(bytes.pack["hh"](258, 772), Bytes(2, 1, 4, 3))
    assert_bytes_equal(bytes.pack["H"](0x10000 - 700), Bytes(68, 253))
    assert_bytes_equal(bytes.pack["i"](1), Bytes(1, 0, 0, 0))
    assert_bytes_equal(bytes.pack["i"](-1), Bytes(255, 255, 255, 255))
    assert_bytes_equal(bytes.pack["i"](70006144), Bytes(128, 53, 44, 4))
    assert_bytes_equal(
        bytes.pack["ii"](16909060, 84281096), Bytes(4, 3, 2, 1, 8, 7, 6, 5)
    )
    assert_bytes_equal(bytes.pack["I"](1), Bytes(1, 0, 0, 0))
    assert_bytes_equal(bytes.pack["I"](4294967295), Bytes(255, 255, 255, 255))
    assert_bytes_equal(bytes.pack["q"](283686952306183), Bytes(7, 6, 5, 4, 3, 2, 1, 0))
    assert_bytes_equal(bytes.pack["l"](70000000), Bytes(128, 29, 44, 4))
    assert_bytes_equal(bytes.pack["l"](-70000000), Bytes(128, 226, 211, 251))
    assert_bytes_equal(bytes.pack["L"](70000000), Bytes(128, 29, 44, 4))


# TODO: Remove this test if the https://github.com/modularml/mojo/pull/3795 is merged
fn test_int_from_bytes() raises:
    assert_equal(bytes.int_from_bytes[DType.int16, big_endian=True](Bytes(0, 16)), 16)
    assert_equal(
        bytes.int_from_bytes[DType.int16, big_endian=False](Bytes(0, 16)), 4096
    )
    assert_equal(
        bytes.int_from_bytes[DType.int16, big_endian=True](Bytes(252, 0)), -1024
    )
    assert_equal(
        bytes.int_from_bytes[DType.uint16, big_endian=True](Bytes(252, 0)), 64512
    )
    assert_equal(
        bytes.int_from_bytes[DType.int16, big_endian=False](Bytes(252, 0)), 252
    )
    assert_equal(
        bytes.int_from_bytes[DType.int32, big_endian=True](Bytes(0, 0, 0, 1)), 1
    )
    assert_equal(
        bytes.int_from_bytes[DType.int32, big_endian=False](Bytes(0, 0, 0, 1)),
        16777216,
    )
    assert_equal(
        bytes.int_from_bytes[DType.int32, big_endian=True](Bytes(1, 0, 0, 0)),
        16777216,
    )
    assert_equal(
        bytes.int_from_bytes[DType.int32, big_endian=True](Bytes(1, 0, 0, 1)),
        16777217,
    )
    assert_equal(
        bytes.int_from_bytes[DType.int32, big_endian=False](Bytes(1, 0, 0, 1)),
        16777217,
    )
    assert_equal(
        bytes.int_from_bytes[DType.int32, big_endian=True](Bytes(255, 0, 0, 0)),
        -16777216,
    )


# TODO: Remove this test if the https://github.com/modularml/mojo/pull/3795 is merged
fn test_int_as_bytes() raises:
    for x in List[Int](10, 100, -12, 0, 1, -1, 1000, -1000):

        @parameter
        for b in range(2):
            assert_equal(
                bytes.int_from_bytes[DType.int16, big_endian=b](
                    bytes.int_as_bytes[DType.int16, big_endian=b](x)
                ),
                x,
            )


fn test_io() raises:
    test_string_literal_to_bytes()


fn test_string_literal_to_bytes() raises:
    var cases = Dict[String, Bytes]()
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
        assert_true(bytes.bytes_equal(bytes.bytes(c.key), c.value))


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
        assert_true(bytes.bytes_equal(bytes.bytes(c.key), c.value))
