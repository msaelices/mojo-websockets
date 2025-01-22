from testing import assert_true

from websockets.aliases import Bytes
from websockets.utils.bytes import bytes_equal


# Test vector from RFC 6455
alias KEY = "dGhlIHNhbXBsZSBub25jZQ=="
alias ACCEPT = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="


# TODO: Needed as SIMD does not conform EqualityComparableCollectionElement 
# Be aware that Byte is an alias of SIMD[DType.uint8, 1]
fn assert_bytes_equal(a: Bytes, b: Bytes) raises:
    assert_true(bytes_equal(a, b))
