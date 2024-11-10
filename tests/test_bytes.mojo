from sys.info import is_big_endian
from testing import assert_equal, assert_true, assert_false

from websockets.aliases import Bytes
from websockets.utils import bytes


fn test_new_features() raises:
    # Test some of the new features in detail
    # (format, argument, big-endian result, little-endian result, asymmetric)
    tests = List(
        Tuple('b', List(7, ), Bytes(7), Bytes(7), 0),
        Tuple('b', List(-7, ), Bytes(249), Bytes(249), 0),
        Tuple('B', List(7, ), Bytes(7), Bytes(7), 0),
        Tuple('B', List(249, ), Bytes(249), Bytes(249), 0),
        Tuple('h', List(700, ), Bytes(2, 188), Bytes(188, 2), 0),
        Tuple('h', List(-700, ), Bytes(253, 68), Bytes(68, 253), 0),
        Tuple('H', List(700, ), Bytes(2, 188), Bytes(188, 2), 0),
        Tuple('H', List(0x10000-700, ), Bytes(253, 68), Bytes(68, 253), 0),
        Tuple('i', List(1, ), Bytes(0, 0, 0, 1), Bytes(1, 0, 0, 0), 0),
        Tuple('i', List(-1, ), Bytes(255, 255, 255, 255), Bytes(255, 255, 255, 255), 0),
        Tuple('i', List(70006144, ), Bytes(4, 44, 53, 128), Bytes(128, 53, 44, 4), 0),
        Tuple('I', List(1, ), Bytes(0, 0, 0, 1), Bytes(1, 0, 0, 0), 0),
        Tuple('I', List(4294967295, ), Bytes(255, 255, 255, 255), Bytes(255, 255, 255, 255), 0),
        Tuple('q', List(283686952306183, ), Bytes(0, 1, 2, 3, 4, 5, 6, 7), Bytes(7, 6, 5, 4, 3, 2, 1, 0), 0),
        Tuple('i', List(70000000, ), Bytes(4, 44, 29, 128), Bytes(128, 29, 44, 4), 0),
        Tuple('i', List(-70000000, ), Bytes(251, 211, 226, 128), Bytes(128, 226, 211, 251), 0),
        Tuple('I', List(70000000, ), Bytes(4, 44, 29, 128), Bytes(128, 29, 44, 4), 0),
        Tuple('I', List(0x100000000-70000000, ), Bytes(251, 211, 226, 128), Bytes(128, 226, 211, 251), 0),
        Tuple('l', List(70000000, ), Bytes(4, 44, 29, 128), Bytes(128, 29, 44, 4), 0),
        Tuple('l', List(-70000000, ), Bytes(251, 211, 226, 128), Bytes(128, 226, 211, 251), 0),
        Tuple('L', List(70000000, ), Bytes(4, 44, 29, 128), Bytes(128, 29, 44, 4), 0),
        Tuple('L', List(0x100000000-70000000, ), Bytes(251, 211, 226, 128), Bytes(128, 226, 211, 251), 0),
    )
    var i: Int

    for test_ref in tests:
        test = test_ref[]
        fmt, args, big, lil, asy = test
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

