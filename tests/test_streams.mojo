from testing import assert_equal, assert_false, assert_raises

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

#
# from .utils import GeneratorTestCase
#
#
# class StreamReaderTests(GeneratorTestCase):
#     def setUp(self):
#         self.reader = StreamReader()
#
#     def test_read_line_too_long(self):
#         self.reader.feed_data(b"spam\neggs\n")
#
#         gen = self.reader.read_line(2)
#         with self.assertRaises(RuntimeError) as raised:
#             next(gen)
#         self.assertEqual(
#             str(raised.exception),
#             "read 5 bytes, expected no more than 2 bytes",
#         )
#
#     def test_read_line_too_long_need_more_data(self):
#         self.reader.feed_data(b"spa")
#
#         gen = self.reader.read_line(2)
#         with self.assertRaises(RuntimeError) as raised:
#             next(gen)
#         self.assertEqual(
#             str(raised.exception),
#             "read 3 bytes, expected no more than 2 bytes",
#         )
#
#     def test_read_exact(self):
#         self.reader.feed_data(b"spameggs")
#
#         gen = self.reader.read_exact(4)
#         data = self.assertGeneratorReturns(gen)
#         self.assertEqual(data, b"spam")
#
#         gen = self.reader.read_exact(4)
#         data = self.assertGeneratorReturns(gen)
#         self.assertEqual(data, b"eggs")
#
#     def test_read_exact_need_more_data(self):
#         self.reader.feed_data(b"spa")
#
#         gen = self.reader.read_exact(4)
#         self.assertGeneratorRunning(gen)
#         self.reader.feed_data(b"meg")
#         data = self.assertGeneratorReturns(gen)
#         self.assertEqual(data, b"spam")
#
#         gen = self.reader.read_exact(4)
#         self.assertGeneratorRunning(gen)
#         self.reader.feed_data(b"gs")
#         data = self.assertGeneratorReturns(gen)
#         self.assertEqual(data, b"eggs")
#
#     def test_read_exact_not_enough_data(self):
#         self.reader.feed_data(b"spa")
#         self.reader.feed_eof()
#
#         gen = self.reader.read_exact(4)
#         with self.assertRaises(EOFError) as raised:
#             next(gen)
#         self.assertEqual(
#             str(raised.exception),
#             "stream ends after 3 bytes, expected 4 bytes",
#         )
#
#     def test_read_to_eof(self):
#         gen = self.reader.read_to_eof(SIZE)
#
#         self.reader.feed_data(b"spam")
#         self.assertGeneratorRunning(gen)
#
#         self.reader.feed_eof()
#         data = self.assertGeneratorReturns(gen)
#         self.assertEqual(data, b"spam")
#
#     def test_read_to_eof_at_eof(self):
#         self.reader.feed_eof()
#
#         gen = self.reader.read_to_eof(SIZE)
#         data = self.assertGeneratorReturns(gen)
#         self.assertEqual(data, b"")
#
#     def test_read_to_eof_too_long(self):
#         gen = self.reader.read_to_eof(2)
#
#         self.reader.feed_data(b"spam")
#         with self.assertRaises(RuntimeError) as raised:
#             next(gen)
#         self.assertEqual(
#             str(raised.exception),
#             "read 4 bytes, expected no more than 2 bytes",
#         )
#
#     def test_at_eof_after_feed_data(self):
#         gen = self.reader.at_eof()
#         self.assertGeneratorRunning(gen)
#         self.reader.feed_data(b"spam")
#         eof = self.assertGeneratorReturns(gen)
#         self.assertFalse(eof)
#
#     def test_at_eof_after_feed_eof(self):
#         gen = self.reader.at_eof()
#         self.assertGeneratorRunning(gen)
#         self.reader.feed_eof()
#         eof = self.assertGeneratorReturns(gen)
#         self.assertTrue(eof)
#
#     def test_feed_data_after_feed_data(self):
#         self.reader.feed_data(b"spam")
#         self.reader.feed_data(b"eggs")
#
#         gen = self.reader.read_exact(8)
#         data = self.assertGeneratorReturns(gen)
#         self.assertEqual(data, b"spameggs")
#         gen = self.reader.at_eof()
#         self.assertGeneratorRunning(gen)
#
#     def test_feed_eof_after_feed_data(self):
#         self.reader.feed_data(b"spam")
#         self.reader.feed_eof()
#
#         gen = self.reader.read_exact(4)
#         data = self.assertGeneratorReturns(gen)
#         self.assertEqual(data, b"spam")
#         gen = self.reader.at_eof()
#         eof = self.assertGeneratorReturns(gen)
#         self.assertTrue(eof)
#
#     def test_feed_data_after_feed_eof(self):
#         self.reader.feed_eof()
#         with self.assertRaises(EOFError) as raised:
#             self.reader.feed_data(b"spam")
#         self.assertEqual(
#             str(raised.exception),
#             "stream ended",
#         )
#
#     def test_feed_eof_after_feed_eof(self):
#         self.reader.feed_eof()
#         with self.assertRaises(EOFError) as raised:
#             self.reader.feed_eof()
#         self.assertEqual(
#             str(raised.exception),
#             "stream ended",
#         )
#
#     def test_discard(self):
#         gen = self.reader.read_to_eof(SIZE)
#
#         self.reader.feed_data(b"spam")
#         self.reader.discard()
#         self.assertGeneratorRunning(gen)
#
#         self.reader.feed_eof()
#         data = self.assertGeneratorReturns(gen)
#         self.assertEqual(data, b"")
