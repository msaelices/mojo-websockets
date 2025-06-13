from collections import Optional
from memory import UnsafePointer
from testing import assert_equal, assert_true, assert_raises

from websockets.aliases import Bytes
from websockets.utils.bytes import str_to_bytes

from websockets.frames import (
    Close,
    Frame,
    OpCode,
)
from websockets.streams import StreamReader
from websockets.utils.bytes import bytes
from testutils import assert_bytes_equal


fn test_str() raises:
    assert_equal(
        String(Frame(OpCode.OP_TEXT, bytes("Spam"))), "TEXT 'Spam' [text, 4 bytes, ]"
    )
    assert_equal(
        String(Frame(OpCode.OP_TEXT, bytes("Spam"), fin=False)),
        "TEXT 'Spam' [text, 4 bytes, continued]",
    )
    assert_equal(
        String(Frame(OpCode.OP_BINARY, Bytes(31, 32, 33, 34))),
        "BINARY 0x1f 0x20 0x21 0x22 [binary, 4 bytes, ]",
    )
    assert_equal(
        String(Frame(OpCode.OP_BINARY, bytes("Eggs"), fin=False)),
        "BINARY 0x45 0x67 0x67 0x73 [binary, 4 bytes, continued]",
    )
    assert_equal(
        String(Frame(OpCode.OP_CLOSE, bytes(""))),
        "CLOSE NO_STATUS_RCVD (no status received [internal]) [, 0 bytes, ]",
    )
    assert_equal(
        String(Frame(OpCode.OP_CLOSE, bytes("\x03\xe9OK"))),
        "CLOSE GOING_AWAY (going away) OK [, 4 bytes, ]",
    )
    assert_equal(String(Frame(OpCode.OP_PING, bytes(""))), "PING '' [, 0 bytes, ]")
    assert_equal(
        String(Frame(OpCode.OP_PING, bytes("ping"))), "PING 'ping' [text, 4 bytes, ]"
    )
    assert_equal(String(Frame(OpCode.OP_PONG, bytes(""))), "PONG '' [, 0 bytes, ]")
    assert_equal(
        String(Frame(OpCode.OP_PONG, bytes("pong"))), "PONG 'pong' [text, 4 bytes, ]"
    )


fn test_close_serialize() raises:
    assert_bytes_equal(Close(1000, "").serialize(), bytes("\x03\xe8"))
    assert_bytes_equal(Close(1000, "OK").serialize(), bytes("\x03\xe8OK"))


fn parse(data: Bytes, mask: Bool) raises -> Optional[Frame]:
    """
    Parse a frame from a bytestring.
    """
    reader = StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    frame = Frame.parse(
        UnsafePointer(to=reader),
        mask=mask,
    )
    return frame


# fn enforce_mask(mask: Bytes):
#     return unittest.mock.patch("secrets.token_bytes", return_value=mask)


fn assert_frame_data(frame: Frame, data: Bytes, mask: Bool) raises:
    """
    Serializing frame yields data. Parsing data yields frame.
    """
    # Compare frames first, because test failures are easier to read,
    # especially when mask = True.
    parsed_frame = parse(data, mask=mask)
    assert_bytes_equal(parsed_frame.value().data, frame.data)

    # Make masking deterministic by reusing the same "random" mask.
    # This has an effect only when mask is True.

    # mask_bytes = data[2:6] if mask else str_to_bytes("")
    # with enforce_mask(mask_bytes):
    #     serialized = frame.serialize(mask=mask, extensions=extensions)
    # assert_bytes_equal(serialized, data)


fn test_text_unmasked() raises:
    data = Bytes(129, 4) + str_to_bytes("Spam")
    assert_frame_data(
        Frame(OpCode.OP_TEXT, str_to_bytes("Spam")),
        data,
        mask=False,
    )


# class FramesTestCase(GeneratorTestCase):
#     def enforce_mask(self, mask):
#         return unittest.mock.patch("secrets.token_bytes", return_value=mask)
#
#     def parse(self, data, mask, max_size=None, extensions=None):
#         """
#         Parse a frame from a bytestring.
#
#         """
#         reader = StreamReader()
#         reader.feed_data(data)
#         reader.feed_eof()
#         parser = Frame.parse(
#             reader.read_exact, mask=mask, max_size=max_size, extensions=extensions
#         )
#         return self.assert_generator_returns(parser)
#
#     def assert_frame_data(self, frame, data, mask, extensions=None):
#         """
#         Serializing frame yields data. Parsing data yields frame.
#
#         """
#         # Compare frames first, because test failures are easier to read,
#         # especially when mask = True.
#         parsed = self.parse(data, mask=mask, extensions=extensions)
#         self.assertEqual(parsed, frame)
#
#         # Make masking deterministic by reusing the same "random" mask.
#         # This has an effect only when mask is True.
#         mask_bytes = data[2:6] if mask else b""
#         with self.enforce_mask(mask_bytes):
#             serialized = frame.serialize(mask=mask, extensions=extensions)
#         self.assertEqual(serialized, data)
#
#
# class FrameTests(FramesTestCase):
#     def test_text_unmasked(self):
#         self.assert_frame_data(
#             Frame(OpCode.OP_TEXT, b"Spam"),
#             b"\x81\x04Spam",
#             mask=False,
#         )
#
#     def test_text_masked(self):
#         self.assert_frame_data(
#             Frame(OpCode.OP_TEXT, b"Spam"),
#             b"\x81\x84\x5b\xfb\xe1\xa8\x08\x8b\x80\xc5",
#             mask=True,
#         )
#
#     def test_binary_unmasked(self):
#         self.assert_frame_data(
#             Frame(OpCode.OP_BINARY, b"Eggs"),
#             b"\x82\x04Eggs",
#             mask=False,
#         )
#
#     def test_binary_masked(self):
#         self.assert_frame_data(
#             Frame(OpCode.OP_BINARY, b"Eggs"),
#             b"\x82\x84\x53\xcd\xe2\x89\x16\xaa\x85\xfa",
#             mask=True,
#         )
#
#     def test_non_ascii_text_unmasked(self):
#         self.assert_frame_data(
#             Frame(OpCode.OP_TEXT, "café".encode()),
#             b"\x81\x05caf\xc3\xa9",
#             mask=False,
#         )
#
#     def test_non_ascii_text_masked(self):
#         self.assert_frame_data(
#             Frame(OpCode.OP_TEXT, "café".encode()),
#             b"\x81\x85\x64\xbe\xee\x7e\x07\xdf\x88\xbd\xcd",
#             mask=True,
#         )
#
#     def test_close(self):
#         self.assert_frame_data(
#             Frame(OpCode.OP_CLOSE, b""),
#             b"\x88\x00",
#             mask=False,
#         )
#
#     def test_ping(self):
#         self.assert_frame_data(
#             Frame(OpCode.OP_PING, b"ping"),
#             b"\x89\x04ping",
#             mask=False,
#         )
#
#     def test_pong(self):
#         self.assert_frame_data(
#             Frame(OpCode.OP_PONG, b"pong"),
#             b"\x8a\x04pong",
#             mask=False,
#         )
#
#     def test_long(self):
#         self.assert_frame_data(
#             Frame(OpCode.OP_BINARY, 126 * b"a"),
#             b"\x82\x7e\x00\x7e" + 126 * b"a",
#             mask=False,
#         )
#
#     def test_very_long(self):
#         self.assert_frame_data(
#             Frame(OpCode.OP_BINARY, 65536 * b"a"),
#             b"\x82\x7f\x00\x00\x00\x00\x00\x01\x00\x00" + 65536 * b"a",
#             mask=False,
#         )
#
#     def test_payload_too_big(self):
#         with self.assertRaises(PayloadTooBig):
#             self.parse(b"\x82\x7e\x04\x01" + 1025 * b"a", mask=False, max_size=1024)
#
#     def test_bad_reserved_bits(self):
#         for data in [b"\xc0\x00", b"\xa0\x00", b"\x90\x00"]:
#             with self.subTest(data=data):
#                 with self.assertRaises(ProtocolError):
#                     self.parse(data, mask=False)
#
#     def test_good_opcode(self):
#         for opcode in list(range(0x00, 0x03)) + list(range(0x08, 0x0B)):
#             data = bytes([0x80 | opcode, 0])
#             with self.subTest(data=data):
#                 self.parse(data, mask=False)  # does not raise an exception
#
#     def test_bad_opcode(self):
#         for opcode in list(range(0x03, 0x08)) + list(range(0x0B, 0x10)):
#             data = bytes([0x80 | opcode, 0])
#             with self.subTest(data=data):
#                 with self.assertRaises(ProtocolError):
#                     self.parse(data, mask=False)
#
#     def test_mask_flag(self):
#         # Mask flag correctly set.
#         self.parse(b"\x80\x80\x00\x00\x00\x00", mask=True)
#         # Mask flag incorrectly unset.
#         with self.assertRaises(ProtocolError):
#             self.parse(b"\x80\x80\x00\x00\x00\x00", mask=False)
#         # Mask flag correctly unset.
#         self.parse(b"\x80\x00", mask=False)
#         # Mask flag incorrectly set.
#         with self.assertRaises(ProtocolError):
#             self.parse(b"\x80\x00", mask=True)
#
#     def test_control_frame_max_length(self):
#         # At maximum allowed length.
#         self.parse(b"\x88\x7e\x00\x7d" + 125 * b"a", mask=False)
#         # Above maximum allowed length.
#         with self.assertRaises(ProtocolError):
#             self.parse(b"\x88\x7e\x00\x7e" + 126 * b"a", mask=False)
#
#     def test_fragmented_control_frame(self):
#         # Fin bit correctly set.
#         self.parse(b"\x88\x00", mask=False)
#         # Fin bit incorrectly unset.
#         with self.assertRaises(ProtocolError):
#             self.parse(b"\x08\x00", mask=False)
#
#     def test_extensions(self):
#         class Rot13:
#             @staticmethod
#             def encode(frame):
#                 assert frame.opcode == OpCode.OP_TEXT
#                 text = frame.data.decode()
#                 data = codecs.encode(text, "rot13").encode()
#                 return dataclasses.replace(frame, data=data)
#
#             # This extensions is symmetrical.
#             @staticmethod
#             def decode(frame, *, max_size=None):
#                 return Rot13.encode(frame)
#
#         self.assert_frame_data(
#             Frame(OpCode.OP_TEXT, b"hello"),
#             b"\x81\x05uryyb",
#             mask=False,
#             extensions=[Rot13()],
#         )
#
#
# class StrTests(unittest.TestCase):
#     def test_cont_text(self):
#         self.assertEqual(
#             String(Frame(OpCode.OP_CONT, b" cr\xc3\xa8me", fin=False)),
#             "CONT ' crème' [text, 7 bytes, continued]",
#         )
#
#     def test_cont_binary(self):
#         self.assertEqual(
#             String(Frame(OpCode.OP_CONT, b"\xfc\xfd\xfe\xff", fin=False)),
#             "CONT fc fd fe ff [binary, 4 bytes, continued]",
#         )
#
#     def test_cont_binary_from_memoryview(self):
#         self.assertEqual(
#             String(Frame(OpCode.OP_CONT, memoryview(b"\xfc\xfd\xfe\xff"), fin=False)),
#             "CONT fc fd fe ff [binary, 4 bytes, continued]",
#         )
#
#     def test_cont_final_text(self):
#         self.assertEqual(
#             String(Frame(OpCode.OP_CONT, b" cr\xc3\xa8me")),
#             "CONT ' crème' [text, 7 bytes]",
#         )
#
#     def test_cont_final_binary(self):
#         self.assertEqual(
#             String(Frame(OpCode.OP_CONT, b"\xfc\xfd\xfe\xff")),
#             "CONT fc fd fe ff [binary, 4 bytes]",
#         )
#
#     def test_cont_final_binary_from_memoryview(self):
#         self.assertEqual(
#             String(Frame(OpCode.OP_CONT, memoryview(b"\xfc\xfd\xfe\xff"))),
#             "CONT fc fd fe ff [binary, 4 bytes]",
#         )
#
#     def test_cont_text_truncated(self):
#         self.assertEqual(
#             String(Frame(OpCode.OP_CONT, b"caf\xc3\xa9 " * 16, fin=False)),
#             "CONT 'café café café café café café café café café ca..."
#             "fé café café café café ' [text, 96 bytes, continued]",
#         )
#
#     def test_cont_binary_truncated(self):
#         self.assertEqual(
#             String(Frame(OpCode.OP_CONT, bytes(range(256)), fin=False)),
#             "CONT 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f ..."
#             " f8 f9 fa fb fc fd fe ff [binary, 256 bytes, continued]",
#         )
#
#     def test_cont_binary_truncated_from_memoryview(self):
#         self.assertEqual(
#             String(Frame(OpCode.OP_CONT, memoryview(bytes(range(256))), fin=False)),
#             "CONT 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f ..."
#             " f8 f9 fa fb fc fd fe ff [binary, 256 bytes, continued]",
#         )
#
#     def test_text(self):
#         self.assertEqual(
#             String(Frame(OpCode.OP_TEXT, b"caf\xc3\xa9")),
#             "TEXT 'café' [5 bytes]",
#         )
#
#     def test_text_non_final(self):
#         self.assertEqual(
#             String(Frame(OpCode.OP_TEXT, b"caf\xc3\xa9", fin=False)),
#             "TEXT 'café' [5 bytes, continued]",
#         )
#
#     def test_text_truncated(self):
#         self.assertEqual(
#             String(Frame(OpCode.OP_TEXT, b"caf\xc3\xa9 " * 16)),
#             "TEXT 'café café café café café café café café café ca..."
#             "fé café café café café ' [96 bytes]",
#         )
#
#     def test_text_with_newline(self):
#         self.assertEqual(
#             String(Frame(OpCode.OP_TEXT, b"Hello\nworld!")),
#             "TEXT 'Hello\\nworld!' [12 bytes]",
#         )
#
#     def test_binary(self):
#         self.assertEqual(
#             String(Frame(OpCode.OP_BINARY, b"\x00\x01\x02\x03")),
#             "BINARY 00 01 02 03 [4 bytes]",
#         )
#
#     def test_binary_from_memoryview(self):
#         self.assertEqual(
#             String(Frame(OpCode.OP_BINARY, memoryview(b"\x00\x01\x02\x03"))),
#             "BINARY 00 01 02 03 [4 bytes]",
#         )
#
#     def test_binary_non_final(self):
#         self.assertEqual(
#             String(Frame(OpCode.OP_BINARY, b"\x00\x01\x02\x03", fin=False)),
#             "BINARY 00 01 02 03 [4 bytes, continued]",
#         )
#
#     def test_binary_non_final_from_memoryview(self):
#         self.assertEqual(
#             String(Frame(OpCode.OP_BINARY, memoryview(b"\x00\x01\x02\x03"), fin=False)),
#             "BINARY 00 01 02 03 [4 bytes, continued]",
#         )
#
#     def test_binary_truncated(self):
#         self.assertEqual(
#             String(Frame(OpCode.OP_BINARY, bytes(range(256)))),
#             "BINARY 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f ..."
#             " f8 f9 fa fb fc fd fe ff [256 bytes]",
#         )
#
#     def test_binary_truncated_from_memoryview(self):
#         self.assertEqual(
#             String(Frame(OpCode.OP_BINARY, memoryview(bytes(range(256))))),
#             "BINARY 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f ..."
#             " f8 f9 fa fb fc fd fe ff [256 bytes]",
#         )
#
#     def test_close(self):
#         self.assertEqual(
#             String(Frame(OpCode.OP_CLOSE, b"\x03\xe8")),
#             "CLOSE 1000 (OK) [2 bytes]",
#         )
#
#     def test_close_reason(self):
#         self.assertEqual(
#             String(Frame(OpCode.OP_CLOSE, b"\x03\xe9Bye!")),
#             "CLOSE 1001 (going away) Bye! [6 bytes]",
#         )
#
#     def test_ping(self):
#         self.assertEqual(
#             String(Frame(OpCode.OP_PING, b"")),
#             "PING '' [0 bytes]",
#         )
#
#     def test_ping_text(self):
#         self.assertEqual(
#             String(Frame(OpCode.OP_PING, b"ping")),
#             "PING 'ping' [text, 4 bytes]",
#         )
#
#     def test_ping_text_with_newline(self):
#         self.assertEqual(
#             String(Frame(OpCode.OP_PING, b"ping\n")),
#             "PING 'ping\\n' [text, 5 bytes]",
#         )
#
#     def test_ping_binary(self):
#         self.assertEqual(
#             String(Frame(OpCode.OP_PING, b"\xff\x00\xff\x00")),
#             "PING ff 00 ff 00 [binary, 4 bytes]",
#         )
#
#     def test_pong(self):
#         self.assertEqual(
#             String(Frame(OpCode.OP_PONG, b"")),
#             "PONG '' [0 bytes]",
#         )
#
#     def test_pong_text(self):
#         self.assertEqual(
#             String(Frame(OpCode.OP_PONG, b"pong")),
#             "PONG 'pong' [text, 4 bytes]",
