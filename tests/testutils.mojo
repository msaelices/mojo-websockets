from testing import assert_true

from websockets.aliases import Bytes


# Test vector from RFC 6455
alias KEY = "dGhlIHNhbXBsZSBub25jZQ=="
alias ACCEPT = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="


fn is_bytes_equal(a: Bytes, b: Bytes) -> Bool:
    if len(a) != len(b):
        return False

    for i in range(len(a)):
        if a[i] != b[i]:
            return False

    return True

# TODO: Needed as SIMD does not conform EqualityComparableCollectionElement 
# Be aware that Byte is an alias of SIMD[DType.uint8, 1]
fn assert_bytes_equal(a: Bytes, b: Bytes) raises:
    assert_true(is_bytes_equal(a, b))
