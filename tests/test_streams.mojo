from testing import assert_equal, assert_false, assert_raises, assert_true

from websockets.aliases import Bytes
from websockets.utils.bytes import str_to_bytes
from websockets.streams import StreamReader

alias SIZE = 32


fn test_read_line() raises:
    reader = StreamReader()
    reader.feed_data(str_to_bytes("spam\neggs\n"))

    line = reader.read_line(SIZE)
    assert_equal(line.value(), str_to_bytes("spam\n"))

    line = reader.read_line(SIZE)
    assert_equal(line.value(), str_to_bytes("eggs\n"))


fn test_read_line_need_more_data() raises:
    reader = StreamReader()
    reader.feed_data(str_to_bytes("spa"))

    line = reader.read_line(SIZE)
    assert_false(bool(line)) 
    reader.feed_data(str_to_bytes("m\neg"))
    line2 = reader.read_line(SIZE)
    assert_equal(line2.value(), str_to_bytes("spam\n"))

    line3 = reader.read_line(SIZE)
    assert_false(bool(line3)) 
    reader.feed_data(str_to_bytes("gs\n"))
    line4 = reader.read_line(SIZE)
    assert_equal(line4.value(), str_to_bytes("eggs\n"))


fn test_read_line_not_enough_data() raises:
    reader = StreamReader()
    reader.feed_data(str_to_bytes("spa"))
    reader.feed_eof()

    with assert_raises(contains="EOFError: stream ends after 3 bytes, before end of line"):
        _ = reader.read_line(SIZE)


fn test_read_line_too_long() raises:
    reader = StreamReader()
    reader.feed_data(str_to_bytes("spam\neggs\n"))

    with assert_raises(contains="RuntimeError: read 5 bytes, expected no more than 2 bytes"):
        _ = reader.read_line(2)


fn test_read_line_too_long_need_more_data() raises:
    reader = StreamReader()
    reader.feed_data(str_to_bytes("spa"))

    with assert_raises(contains="RuntimeError: read 3 bytes, expected no more than 2 bytes"):
        _ = reader.read_line(2)


fn test_read_exact() raises:
    reader = StreamReader()
    reader.feed_data(str_to_bytes("spameggs"))

    data = reader.read_exact(4)
    assert_equal(data.value(), str_to_bytes("spam"))

    data = reader.read_exact(4)
    assert_equal(data.value(), str_to_bytes("eggs"))


fn test_read_exact_need_more_data() raises:
    reader = StreamReader()
    reader.feed_data(str_to_bytes("spa"))

    data = reader.read_exact(4)
    assert_false(bool(data))
    reader.feed_data(str_to_bytes("meg"))
    data = reader.read_exact(4)
    assert_equal(data.value(), str_to_bytes("spam"))

    data = reader.read_exact(4)
    assert_false(bool(data))
    reader.feed_data(str_to_bytes("gs"))
    data = reader.read_exact(4)
    assert_equal(data.value(), str_to_bytes("eggs"))


fn test_read_exact_not_enough_data() raises:
    reader = StreamReader()
    reader.feed_data(str_to_bytes("spa"))
    reader.feed_eof()

    with assert_raises(contains="EOFError: stream ends after 3 bytes, expected 4 bytes"):
        _ = reader.read_exact(4)


fn test_read_to_eof() raises:
    reader = StreamReader()
    data = reader.read_to_eof(SIZE)
    assert_false(bool(data))
    reader.feed_data(str_to_bytes("spam"))
    reader.feed_eof()
    data = reader.read_to_eof(SIZE)
    assert_equal(data.value(), str_to_bytes("spam"))

fn test_read_to_eof_at_eof() raises:
    reader = StreamReader()
    reader.feed_eof()

    data = reader.read_to_eof(SIZE)
    assert_equal(data.value(), str_to_bytes(""))


fn test_read_to_eof_too_long() raises:
    reader = StreamReader()

    reader.feed_data(str_to_bytes("spam"))
    with assert_raises(contains="RuntimeError: read 4 bytes, expected no more than 2 bytes"):
        _ = reader.read_to_eof(2)


fn test_feed_data_after_feed_data() raises:
    reader = StreamReader()
    reader.feed_data(str_to_bytes("spam"))
    reader.feed_data(str_to_bytes("eggs"))

    data = reader.read_exact(8)
    assert_equal(data.value(), str_to_bytes("spameggs"))
    eof = reader.at_eof()
    assert_false(eof)


fn test_feed_eof_after_feed_data() raises:
    reader = StreamReader()
    reader.feed_data(str_to_bytes("spam"))
    reader.feed_eof()

    data = reader.read_exact(4)
    assert_equal(data.value(), str_to_bytes("spam"))
    eof = reader.at_eof()
    assert_true(eof)


fn test_at_eof_after_feed_data() raises:
    reader = StreamReader()
    eof = reader.at_eof()
    assert_false(eof)
    reader.feed_data(str_to_bytes("spam"))
    eof = reader.at_eof()
    assert_false(eof)


fn test_at_eof_after_feed_eof() raises:
    reader = StreamReader()
    eof = reader.at_eof()
    assert_false(eof)
    reader.feed_eof()
    eof = reader.at_eof()
    assert_true(eof)


fn test_feed_data_after_feed_eof() raises:
    reader = StreamReader()
    reader.feed_eof()
    with assert_raises(contains="EOFError: stream ended"):
        reader.feed_data(str_to_bytes("spam"))


fn test_feed_eof_after_feed_eof() raises:
    reader = StreamReader()
    reader.feed_eof()
    with assert_raises(contains="EOFError: stream ended"):
        reader.feed_eof()


fn test_discard() raises:
    reader = StreamReader()
    data = reader.read_to_eof(SIZE)

    reader.feed_data(str_to_bytes("spam"))
    reader.discard()
    reader.feed_eof()
    data = reader.read_to_eof(SIZE)
    assert_equal(data.value(), str_to_bytes(""))

