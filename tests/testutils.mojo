from builtin._location import __call_location
from testing import assert_true

from websockets.aliases import Bytes
from websockets.utils.bytes import bytes_equal

# Test vector from RFC 6455
alias KEY = "dGhlIHNhbXBsZSBub25jZQ=="
alias ACCEPT = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="


# TODO: Needed as SIMD does not conform EqualityComparableCollectionElement
# Be aware that Byte is an alias of SIMD[DType.uint8, 1]
@always_inline
fn assert_bytes_equal(a: Bytes, b: Bytes) raises:
    assert_true(
        val=bytes_equal(a, b),
        msg=String(
            "Expected first with {} bytes to be equal to second with {} ones"
        ).format(len(a), len(b)),
        location=__call_location(),
    )
