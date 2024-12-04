from sys.info import is_big_endian
from testing import assert_equal, assert_true, assert_false

from websockets.aliases import Bytes
from websockets.utils import bytes


fn test_unpack() raises:
    # Test some of the unpack features in detail
    # (format, argument, big-endian result, little-endian result)
    tests = List(
        Tuple('b', List(7, ), Bytes(7), Bytes(7)),
        Tuple('b', List(-7, ), Bytes(249), Bytes(249)),
        Tuple('B', List(7, ), Bytes(7), Bytes(7)),
        Tuple('B', List(249, ), Bytes(249), Bytes(249)),
        Tuple('h', List(700, ), Bytes(2, 188), Bytes(188, 2)),
        Tuple('h', List(-700, ), Bytes(253, 68), Bytes(68, 253)),
        Tuple('hh', List(258, 772), Bytes(1, 2, 3, 4), Bytes(2, 1, 4, 3)),
        Tuple('H', List(700, ), Bytes(2, 188), Bytes(188, 2)),
        Tuple('H', List(0x10000-700, ), Bytes(253, 68), Bytes(68, 253)),
        Tuple('i', List(1, ), Bytes(0, 0, 0, 1), Bytes(1, 0, 0, 0)),
        Tuple('i', List(-1, ), Bytes(255, 255, 255, 255), Bytes(255, 255, 255, 255)),
        Tuple('i', List(70006144, ), Bytes(4, 44, 53, 128), Bytes(128, 53, 44, 4)),
        Tuple('ii', List(16909060, 84281096), Bytes(1, 2, 3, 4, 5, 6, 7, 8), Bytes(4, 3, 2, 1, 8, 7, 6, 5)),
        Tuple('I', List(1, ), Bytes(0, 0, 0, 1), Bytes(1, 0, 0, 0)),
        Tuple('I', List(4294967295, ), Bytes(255, 255, 255, 255), Bytes(255, 255, 255, 255)),
        Tuple('q', List(283686952306183, ), Bytes(0, 1, 2, 3, 4, 5, 6, 7), Bytes(7, 6, 5, 4, 3, 2, 1, 0)),
        Tuple('i', List(70000000, ), Bytes(4, 44, 29, 128), Bytes(128, 29, 44, 4)),
        Tuple('i', List(-70000000, ), Bytes(251, 211, 226, 128), Bytes(128, 226, 211, 251)),
        Tuple('I', List(70000000, ), Bytes(4, 44, 29, 128), Bytes(128, 29, 44, 4)),
        Tuple('I', List(0x100000000-70000000, ), Bytes(251, 211, 226, 128), Bytes(128, 226, 211, 251)),
        Tuple('l', List(70000000, ), Bytes(4, 44, 29, 128), Bytes(128, 29, 44, 4)),
        Tuple('l', List(-70000000, ), Bytes(251, 211, 226, 128), Bytes(128, 226, 211, 251)),
        Tuple('L', List(70000000, ), Bytes(4, 44, 29, 128), Bytes(128, 29, 44, 4)),
        Tuple('L', List(0x100000000-70000000, ), Bytes(251, 211, 226, 128), Bytes(128, 226, 211, 251)),
    )
    var i: Int

    for test_ref in tests:
        test = test_ref[]
        fmt, args, big, lil = test
        for op_ref in List(
             Tuple('>{}'.format(fmt), big),
             Tuple('!{}'.format(fmt), big),
             Tuple('<{}'.format(fmt), lil),
             Tuple('={}'.format(fmt), big if is_big_endian() else lil)
        ):
            op = op_ref[]
            xfmt, exp = op
            values = bytes.unpack(xfmt, exp)
            i = 0
            assert_equal(len(values), len(args))
            for value_ref in values:
                value = value_ref[]
                assert_equal(args[i], value, "unpack({!r}, {!r})".format(xfmt, String(exp)))
                i += 1
        #     print(xfmt, exp)
            # res = bytes.pack(xfmt, arg)
            # assert_equal(res, exp)
        #     assert_equal(struct.calcsize(xfmt), len(res))
            # rev = bytes.unpack(xfmt, res)[0]
            # if rev != arg:
            #     assert_true(asy)

fn test_pack() raises:
    assert_equal(bytes.pack['b'](7), Bytes(7))
    assert_equal(bytes.pack['b'](-7), Bytes(249))
    assert_equal(bytes.pack['B'](7), Bytes(7))
    assert_equal(bytes.pack['B'](249), Bytes(249))
    assert_equal(bytes.pack['h'](700), Bytes(188, 2))
    assert_equal(bytes.pack['H'](700), Bytes(188, 2))
    assert_equal(bytes.pack['h'](-700), Bytes(68, 253))
    assert_equal(bytes.pack['hh'](258, 772), Bytes(2, 1, 4, 3))
    assert_equal(bytes.pack['H'](0x10000-700), Bytes(68, 253))
    assert_equal(bytes.pack['i'](1), Bytes(1, 0, 0, 0))
    assert_equal(bytes.pack['i'](-1), Bytes(255, 255, 255, 255))
    assert_equal(bytes.pack['i'](70006144), Bytes(128, 53, 44, 4))
    assert_equal(bytes.pack['ii'](16909060, 84281096), Bytes(4, 3, 2, 1, 8, 7, 6, 5))
    assert_equal(bytes.pack['I'](1), Bytes(1, 0, 0, 0))
    assert_equal(bytes.pack['I'](4294967295), Bytes(255, 255, 255, 255))
    assert_equal(bytes.pack['q'](283686952306183), Bytes(7, 6, 5, 4, 3, 2, 1, 0))
    assert_equal(bytes.pack['l'](70000000), Bytes(128, 29, 44, 4))
    assert_equal(bytes.pack['l'](-70000000), Bytes(128, 226, 211, 251))
    assert_equal(bytes.pack['L'](70000000), Bytes(128, 29, 44, 4))


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
    for x_ref in List[Int](10, 100, -12, 0, 1, -1, 1000, -1000):
        x = x_ref[]

        @parameter
        for b in range(2):
            assert_equal(
                bytes.int_from_bytes[DType.int16, big_endian=b](
                    bytes.int_as_bytes[DType.int16, big_endian=b](x)
                ),
                x,
            )
    
