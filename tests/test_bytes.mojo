from sys.info import is_big_endian
from testing import assert_equal, assert_true, assert_false

from websockets.aliases import Bytes
from websockets.utils import bytes


fn test_new_features() raises:
    # Test some of the new features in detail
    # (format, argument, big-endian result, little-endian result, asymmetric)
    tests = List(
        # ('c', b'a', b'a', b'a', 0),
        # ('xc', b'a', b'\0a', b'\0a', 0),
        # ('cx', b'a', b'a\0', b'a\0', 0),
        # ('s', b'a', b'a', b'a', 0),
        # Tuple('0s', 'helloworld', '', '', 1),
        # ('1s', b'helloworld', b'h', b'h', 1),
        # ('9s', b'helloworld', b'helloworl', b'helloworl', 1),
        # ('10s', b'helloworld', b'helloworld', b'helloworld', 0),
        # ('11s', b'helloworld', b'helloworld\0', b'helloworld\0', 1),
        # ('20s', b'helloworld', b'helloworld'+10*b'\0', b'helloworld'+10*b'\0', 1),
        Tuple('b', 7, Bytes(7), Bytes(7), 0),
        Tuple('b', -7, Bytes(249), Bytes(249), 0),
        Tuple('B', 7, Bytes(7), Bytes(7), 0),
        Tuple('B', 249, Bytes(249), Bytes(249), 0),
        # Tuple('h', 700, '0b\002\274', '0b\274\002', 0),
        # Tuple('h', -700, '0b\375D', '0bD\375', 0),
        # Tuple('H', 700, '0b\002\274', '0b\274\002', 0),
        # Tuple('H', 0x10000-700, '0b\375D', '0bD\375', 0),
        # ('i', 70000000, b'\004,\035\200', b'\200\035,\004', 0),
        # ('i', -70000000, b'\373\323\342\200', b'\200\342\323\373', 0),
        # ('I', 70000000, b'\004,\035\200', b'\200\035,\004', 0),
        # ('I', 0x100000000-70000000, b'\373\323\342\200', b'\200\342\323\373', 0),
        # ('l', 70000000, b'\004,\035\200', b'\200\035,\004', 0),
        # ('l', -70000000, b'\373\323\342\200', b'\200\342\323\373', 0),
        # ('L', 70000000, b'\004,\035\200', b'\200\035,\004', 0),
        # ('L', 0x100000000-70000000, b'\373\323\342\200', b'\200\342\323\373', 0),
        # ('f', 2.0, b'@\000\000\000', b'\000\000\000@', 0),
        # ('d', 2.0, b'@\000\000\000\000\000\000\000',
        #            b'\000\000\000\000\000\000\000@', 0),
        # ('f', -2.0, b'\300\000\000\000', b'\000\000\000\300', 0),
        # ('d', -2.0, b'\300\000\000\000\000\000\000\000',
        #             b'\000\000\000\000\000\000\000\300', 0),
        # ('?', 0, b'\0', b'\0', 0),
        # ('?', 3, b'\1', b'\1', 1),
        # ('?', True, b'\1', b'\1', 0),
        # ('?', [], b'\0', b'\0', 1),
        # ('?', (1,), b'\1', b'\1', 1),
    )

    for test_ref in tests:
        test = test_ref[]
        fmt, arg, big, lil, asy = test
        for op_ref in List(
             Tuple('>{}'.format(fmt), big),
             Tuple('!{}'.format(fmt), big),
             Tuple('<{}'.format(fmt), lil),
             Tuple('={}'.format(fmt), big if is_big_endian() else lil)
        ):
            op = op_ref[]
            xfmt, exp = op
            assert_equal(arg, bytes.unpack(xfmt, exp)[0])
        #     print(xfmt, exp)
            # res = bytes.pack(xfmt, arg)
            # assert_equal(res, exp)
        #     assert_equal(struct.calcsize(xfmt), len(res))
            # rev = bytes.unpack(xfmt, res)[0]
            # if rev != arg:
            #     assert_true(asy)

