from testing import assert_equal, assert_false, assert_true, assert_raises

from websockets.aliases import Bytes
from websockets.http import Header, Headers
from websockets.frames import OP_TEXT, Frame
from websockets.http import HTTPRequest, HTTPResponse
from websockets.protocol import CONNECTING, OPEN, Event
from websockets.protocol.base import (
    close_expected,
    receive_data,
    receive_eof,
)
from websockets.protocol.server import ServerProtocol
from websockets.utils.bytes import str_to_bytes
from websockets.utils.uri import URI

from testutils import ACCEPT, KEY


fn date_func() -> String:
    return "Thu, 02 Jan 2025 22:16:23 GMT"

fn make_request() raises -> HTTPRequest:
    """Generate a handshake request that can be altered for testing."""
    return HTTPRequest(
        uri=URI.parse_raises("/test"),
        headers=Headers(
            Header("Host", "example.com"),
            Header("Upgrade", "websocket"),
            Header("Connection", "Upgrade"),
            Header("Sec-WebSocket-Key", KEY),
            Header("Sec-WebSocket-Version", "13"),
        ),
    )


fn test_receive_request() raises:
    """Server receives a handshake request."""
    server = ServerProtocol()
    receive_data(
        server,
        str_to_bytes(
            "GET /test HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: {}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n".format(KEY)
        )
    )

    data_to_send = server.data_to_send()
    assert_equal(data_to_send, Bytes())
    assert_false(close_expected(server))
    assert_equal(server.get_state(), CONNECTING)


fn test_accept_and_send_successful_response() raises:
    """Server accepts a handshake request and sends a successful response."""
    server = ServerProtocol()
    request = make_request()
    response = server.accept[date_func=date_func](request)
    server.send_response(response)

    data_to_send = server.data_to_send()
    expected = str_to_bytes(
        "HTTP/1.1 101 Switching Protocols\r\n"
        "date: Thu, 02 Jan 2025 22:16:23 GMT\r\n"
        "upgrade: websocket\r\n"
        "connection: Upgrade\r\n"
        "sec-websocket-accept: {}\r\n"
        "\r\n".format(ACCEPT)
    )
    assert_equal(
        data_to_send,
        expected,
    )
    assert_false(close_expected(server))
    assert_equal(server.get_state(), OPEN)


fn test_send_response_after_failed_accept() raises:
    """Server accepts a handshake request but sends a failed response."""
    var server = ServerProtocol()
    var request = make_request()
    request.headers.remove("Sec-WebSocket-Key")
    var response = server.accept[date_func=date_func](request)
    server.send_response(response)

    var data_to_send = server.data_to_send()
    assert_equal(
        data_to_send,
        str_to_bytes(
            "HTTP/1.1 400 Bad Request\r\n"
            "date: Thu, 02 Jan 2025 22:16:23 GMT\r\n"
            "connection: close\r\n"
            "content-length: 35\r\n"
            "content-type: text/plain; charset=utf-8\r\n"
            "\r\n"
            'Missing "Sec-WebSocket-Key" header.'
        )
    )
    assert_true(close_expected(server))
    assert_equal(server.get_state(), CONNECTING)


fn test_send_response_after_reject() raises:
    """Server rejects a handshake request and sends a failed response."""
    var server = ServerProtocol()
    var response = server.reject[date_func=date_func](404, "Not Found", "Sorry folks.\n")
    server.send_response(response)

    var data_to_send = server.data_to_send()
    assert_equal(
        data_to_send,
        str_to_bytes(
            "HTTP/1.1 404 Not Found\r\n"
            "date: Thu, 02 Jan 2025 22:16:23 GMT\r\n"
            "connection: close\r\n"
            "content-length: 13\r\n"
            "content-type: text/plain; charset=utf-8\r\n"
            "\r\n"
            "Sorry folks.\n"
        )
    )
    assert_true(close_expected(server))
    assert_equal(server.get_state(), CONNECTING)


fn test_send_response_without_accept_or_reject() raises:
    """Server doesn't accept or reject and sends a failed response."""
    var server = ServerProtocol()
    server.send_response(
        HTTPResponse(
            410,
            "Gone",
            Headers(
                Header("Connection", "close"),
                Header("Content-Length", "6"),
                Header("Content-Type", "text/plain"),
                Header("Date", date_func()),
            ),
            str_to_bytes("AWOL.\n"),
        )
    )

    var data_to_send = server.data_to_send()
    assert_equal(
        data_to_send,
        str_to_bytes(
            "HTTP/1.1 410 Gone\r\n"
            "connection: close\r\n"
            "content-length: 6\r\n"
            "content-type: text/plain\r\n"
            "date: {}\r\n"
            "\r\n"
            "AWOL.\n".format(date_func())
        )
    )
    assert_true(close_expected(server))
    assert_equal(server.get_state(), CONNECTING)


fn test_receive_request_and_check_events() raises:
    """Server receives a handshake request and checks events."""
    var server = ServerProtocol()
    receive_data(
        server,
        str_to_bytes(
            "GET /test HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: {}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n".format(KEY)
        )
    )

    var events = server.events_received()
    assert_equal(len(events), 1)

    var request = events[0][HTTPRequest]
    assert_equal(request.uri.get_path(), "/test")
    assert_equal(
        request.headers,
        Headers(
            Header("Host", "example.com"),
            Header("Upgrade", "websocket"),
            Header("Connection", "Upgrade"),
            Header("Sec-WebSocket-Key", KEY),
            Header("Sec-WebSocket-Version", "13")
        )
    )
    assert_false(server.get_handshake_exc())


fn test_receive_no_request() raises:
    """Server receives no handshake request."""
    var server = ServerProtocol()
    receive_eof(server)

    assert_true(server.get_handshake_exc())
    # TODO: Original Python error was
    # EOFError: connection closed while reading HTTP request line
    assert_equal(
        str(server.get_handshake_exc().value()),
        "EOFError: connection closed before handshake completed"
    )
    var events = server.events_received()
    assert_equal(len(events), 0)


fn test_receive_truncated_request() raises:
    """Server receives a truncated handshake request."""
    var server = ServerProtocol()
    receive_data(server, str_to_bytes("GET /test HTTP/1.1\r\n"))
    assert_false(server.get_handshake_exc())

    receive_eof(server)
    assert_true(server.get_handshake_exc())
    # TODO: Original Python error was
    # EOFError: connection closed while reading HTTP headers
    assert_equal(
        str(server.get_handshake_exc().value()),
        "EOFError: connection closed before handshake completed"
    )
    var data_to_send = server.data_to_send()
    assert_equal(data_to_send, Bytes())
    var events = server.events_received()
    assert_equal(len(events), 1)
    assert_true(events[0].isa[HTTPRequest]())


fn test_receive_junk_request() raises:
    """Server receives a junk handshake request."""
    var server = ServerProtocol()
    receive_data(server, str_to_bytes("HELO relay.invalid\r\n"))
    receive_data(server, str_to_bytes("MAIL FROM: <alice@invalid>\r\n"))
    receive_data(server, str_to_bytes("RCPT TO: <bob@invalid>\r\n"))

    var events = server.events_received()
    assert_true(server.get_handshake_exc())
    # TODO: Original Python error was
    # ValueError: invalid HTTP request line: HELO relay.invalid
    assert_equal(
        str(server.get_handshake_exc().value()),
        "ValueError: Failed to parse request headers: Failed to read third word from request line"
    )
    assert_equal(len(events), 2)
    assert_true(events[0].isa[HTTPRequest]())
    assert_true(events[1].isa[HTTPRequest]())

# ===----------------------------------------------------------------------===
# Test generating opening handshake responses.
# ===----------------------------------------------------------------------===


fn test_accept_response() raises:
    """Check that `accept()` creates a successful opening handshake response."""
    var server = ServerProtocol()
    var request = make_request()
    var response = server.accept[date_func=date_func](request)

    assert_equal(response.status_code, 101)
    assert_equal(response.status_text, "Switching Protocols")
    assert_equal(
        response.headers,
        Headers(
            Header("Date", date_func()),
            Header("Upgrade", "websocket"),
            Header("Connection", "Upgrade"),
            Header("Sec-WebSocket-Accept", ACCEPT),
        )
    )
    assert_equal(response.body_raw, Bytes())


fn test_reject_response() raises:
    """Check that `reject()` creates a failed opening handshake response."""
    var server = ServerProtocol()
    var response = server.reject[date_func=date_func](404, "Not Found", "Sorry folks.\n")

    assert_equal(response.status_code, 404)
    assert_equal(response.status_text, "Not Found")
    assert_equal(
        response.headers,
        Headers(
            Header("Date", date_func()),
            Header("Connection", "close"),
            Header("Content-Length", "13"),
            Header("Content-Type", "text/plain; charset=utf-8"),
        )
    )
    assert_equal(response.body_raw, str_to_bytes("Sorry folks.\n"))


fn test_reject_response_supports_int_status() raises:
    """Check that reject() accepts an integer status code."""
    var server = ServerProtocol()
    var response = server.reject[date_func=date_func](404, "Not Found", "Sorry folks.\n")

    assert_equal(response.status_code, 404)
    assert_equal(response.status_text, "Not Found")


# TODO: Implement this tests when we can mock the process_request function
# fn test_unexpected_error() raises:
#     """Check that accept() handles unexpected errors and returns an error response."""
#     var server = ServerProtocol()
#     var request = make_request()
#     # TODO: Mock process_request to raise an exception
#     # process_request.side_effect = (Exception("BOOM"),)
#     var response = server.accept[date_func=date_func](request)
#
#     assert_equal(response.status_code, 500)
#     assert_true(server.get_handshake_exc())
#     assert_equal(str(server.get_handshake_exc().value()), "Exception: BOOM")


# ===----------------------------------------------------------------------===
# Test processing of handshake responses to configure the connection.
# ===----------------------------------------------------------------------===

#     def assertHandshakeSuccess(self, server):
#         """Assert that the opening handshake succeeded."""
#         self.assertEqual(server.state, OPEN)
#         self.assertIsNone(server.handshake_exc)

#     def assertHandshakeError(self, server, exc_type, msg):
#         """Assert that the opening handshake failed with the given exception."""
#         self.assertEqual(server.state, CONNECTING)
#         self.assertIsInstance(server.handshake_exc, exc_type)
#         exc = server.handshake_exc
#         exc_str = str(exc)
#         while exc.__cause__ is not None:
#             exc = exc.__cause__
#             exc_str += "; " + str(exc)
#         self.assertEqual(exc_str, msg)


fn test_basic() raises:
    """Handshake succeeds."""
    var server = ServerProtocol()
    var request = make_request()
    var response = server.accept[date_func=date_func](request)
    server.send_response(response)

    assert_equal(server.get_state(), OPEN)
    assert_false(server.get_handshake_exc())


fn test_missing_connection() raises:
    """Handshake fails when the Connection header is missing."""
    var server = ServerProtocol()
    var request = make_request()
    request.headers.remove("Connection")
    var response = server.accept[date_func=date_func](request)
    server.send_response(response)

    # TODO: It should return 426 but it returns 400 because we cannot handle
    # specific errors yet in Mojo
    assert_equal(response.status_code, 400)
    assert_true(server.get_handshake_exc())
    assert_equal(
        str(server.get_handshake_exc().value()),
        'Request headers do not contain an "connection" header'
    )


fn test_invalid_connection() raises:
    """Handshake fails when the Connection header is invalid."""
    var server = ServerProtocol()
    var request = make_request()
    request.headers["Connection"] = "close"
    var response = server.accept[date_func=date_func](request)
    server.send_response(response)

    # TODO: It should return 426 but it returns 400 because we cannot handle
    # specific errors yet in Mojo
    assert_equal(response.status_code, 400)
    assert_true(server.get_handshake_exc())
    # TODO: Original Python error was
    # Request headers do not contain an "connection" header
    assert_equal(
        str(server.get_handshake_exc().value()),
        'Request "connection" header is not "upgrade"'
    )


fn test_missing_upgrade() raises:
    """Handshake fails when the Upgrade header is missing."""
    var server = ServerProtocol()
    var request = make_request()
    request.headers.remove("Upgrade")
    var response = server.accept[date_func=date_func](request)
    server.send_response(response)

    # TODO: It should return 426 but it returns 400 because we cannot handle
    # specific errors yet in Mojo
    assert_equal(response.status_code, 400)
    assert_true(server.get_handshake_exc())
    assert_equal(
        str(server.get_handshake_exc().value()),
        'Request headers do not contain an "upgrade" header'
    )


fn test_invalid_upgrade() raises:
    """Handshake fails when the Upgrade header is invalid."""
    var server = ServerProtocol()
    var request = make_request()
    request.headers.remove("Upgrade")
    request.headers["Upgrade"] = "h2c"
    var response = server.accept[date_func=date_func](request)
    server.send_response(response)

    # TODO: It should return 426 but it returns 400 because we cannot handle
    # specific errors yet in Mojo
    assert_equal(response.status_code, 400)
    assert_true(server.get_handshake_exc())
    assert_equal(
        str(server.get_handshake_exc().value()),
        'Request "upgrade" header is not "websocket"'
    )


fn test_missing_key() raises:
    """Handshake fails when the Sec-WebSocket-Key header is missing."""
    var server = ServerProtocol()
    var request = make_request()
    request.headers.remove("Sec-WebSocket-Key")
    var response = server.accept[date_func=date_func](request)
    server.send_response(response)

    assert_equal(response.status_code, 400)
    assert_true(server.get_handshake_exc())
    assert_equal(
        str(server.get_handshake_exc().value()),
        'Missing "Sec-WebSocket-Key" header.'
    )


# TODO: The current HTTPRequest implementation does not support multiple headers
# So this test is not possible to implement yet
# fn test_multiple_key() raises:
#     """Handshake fails when the Sec-WebSocket-Key header is repeated."""
#     var server = ServerProtocol()
#     var request = make_request()
#     request.headers["Sec-WebSocket-Key"] = KEY
#     var response = server.accept[date_func=date_func](request)
#     server.send_response(response)
#
#     assert_equal(response.status_code, 400)
#     assert_true(server.get_handshake_exc())
#     assert_equal(
#         str(server.get_handshake_exc().value()),
#         "invalid Sec-WebSocket-Key header: multiple values"
#     )


fn test_invalid_key() raises:
    """Handshake fails when the Sec-WebSocket-Key header is invalid."""
    var server = ServerProtocol()
    var request = make_request()
    request.headers.remove("Sec-WebSocket-Key")
    request.headers["Sec-WebSocket-Key"] = "<no Base64 data>"
    var response = server.accept[date_func=date_func](request)
    server.send_response(response)

    assert_equal(response.status_code, 400)
    assert_true(server.get_handshake_exc())
    assert_equal(
        str(server.get_handshake_exc().value()),
        "ValueError: Unexpected character encountered",
    )


fn test_truncated_key() raises:
    """Handshake fails when the Sec-WebSocket-Key header is truncated."""
    var server = ServerProtocol()
    var request = make_request()
    request.headers.remove("Sec-WebSocket-Key")
    # 13 bytes instead of 16, Base64-encoded
    key = String(KEY)[:13]
    request.headers["Sec-WebSocket-Key"] = key
    var response = server.accept[date_func=date_func](request)
    server.send_response(response)

    assert_equal(response.status_code, 400)
    assert_true(server.get_handshake_exc())
    assert_equal(
        str(server.get_handshake_exc().value()),
        "ValueError: Input length must be divisible by 4"
    )


fn test_missing_version() raises:
    """Handshake fails when the Sec-WebSocket-Version header is missing."""
    var server = ServerProtocol()
    var request = make_request()
    request.headers.remove("Sec-WebSocket-Version")
    var response = server.accept[date_func=date_func](request)
    server.send_response(response)

    assert_equal(response.status_code, 400)
    assert_true(server.get_handshake_exc())
    assert_equal(
        str(server.get_handshake_exc().value()),
        'Missing "Sec-WebSocket-Version" header.'
    )


fn test_invalid_version() raises:
    """Handshake fails when the Sec-WebSocket-Version header is invalid."""
    var server = ServerProtocol()
    var request = make_request()
    request.headers.remove("Sec-WebSocket-Version")
    request.headers["Sec-WebSocket-Version"] = "11"
    var response = server.accept[date_func=date_func](request)
    server.send_response(response)

    assert_equal(response.status_code, 400)
    assert_true(server.get_handshake_exc())
    assert_equal(
        str(server.get_handshake_exc().value()),
        'Request "Sec-WebSocket-Version" header is not "13"'
    )


fn test_origin() raises:
    """Handshake succeeds when checking origin."""
    var server = ServerProtocol(origins=List(String("https://example.com")))
    var request = make_request()
    request.headers["Origin"] = "https://example.com"
    var response = server.accept[date_func=date_func](request)
    server.send_response(response)

    assert_equal(server.get_state(), OPEN)
    assert_false(server.get_handshake_exc())
    # TODO: Set the origin in the server after parsing the request?
    # Not sure why we need the server.origin attribute
    # assert_equal(server.origin.value(), "https://example.com")


fn test_no_origin() raises:
    """Handshake fails when checking origin and the Origin header is missing."""
    var server = ServerProtocol(origins=List(String("https://example.com")))
    var request = make_request()
    var response = server.accept[date_func=date_func](request)
    server.send_response(response)

    # TODO: It should return 403 but it returns 400 because we cannot handle
    # specific errors yet in Mojo
    assert_equal(response.status_code, 400)
    assert_true(server.get_handshake_exc())
    assert_equal(
        str(server.get_handshake_exc().value()),
        'Missing "Origin" header.'
    )


fn test_unexpected_origin() raises:
    """Handshake fails when checking origin and the Origin header is unexpected."""
    var server = ServerProtocol(origins=List(String("https://example.com")))
    var request = make_request()
    request.headers["Origin"] = "https://other.example.com"
    var response = server.accept[date_func=date_func](request)
    server.send_response(response)

    # TODO: It should return 403 but it returns 400 because we cannot handle
    # specific errors yet in Mojo
    assert_equal(response.status_code, 400)
    assert_true(server.get_handshake_exc())
    assert_equal(
        str(server.get_handshake_exc().value()),
        'Invalid "Origin" header: https://other.example.com'
    )


fn test_supported_origin() raises:
    """Handshake succeeds when checking origins and the origin is supported."""
    var server = ServerProtocol(origins=List[String]("https://example.com", "https://other.example.com"))
    var request = make_request()
    request.headers["Origin"] = "https://other.example.com"
    var response = server.accept[date_func=date_func](request)
    server.send_response(response)

    assert_equal(server.get_state(), OPEN)
    assert_false(server.get_handshake_exc())

    # TODO: Set the origin in the server after parsing the request?
    # Not sure why we need the server.origin attribute
    # assert_equal(server.origin.value(), "https://example.com")


fn test_unsupported_origin() raises:
    """Handshake succeeds when checking origins and the origin is unsupported."""
    var server = ServerProtocol(origins=List[String]("https://example.com", "https://other.example.com"))
    var request = make_request()
    request.headers["Origin"] = "https://original.example.com"
    var response = server.accept[date_func=date_func](request)
    server.send_response(response)

    # TODO: It should return 403 but it returns 400 because we cannot handle
    # specific errors yet in Mojo
    assert_equal(response.status_code, 400)
    assert_true(server.get_handshake_exc())
    assert_equal(
        str(server.get_handshake_exc().value()),
        'Invalid "Origin" header: https://original.example.com'
    )


fn test_no_origin_accepted() raises:
    """Handshake succeeds when the lack of an origin is accepted."""
    var server = ServerProtocol(origins=None)
    var request = make_request()
    var response = server.accept[date_func=date_func](request)
    server.send_response(response)

    assert_equal(server.get_state(), OPEN)
    assert_false(server.get_handshake_exc())

    # TODO: Set the origin in the server after parsing the request?
    # Not sure why we need the server.origin attribute
    # assert_equal(server.origin, None)

#     def test_no_extensions(self):
#         """Handshake succeeds without extensions."""
#         server = ServerProtocol()
#         request = make_request()
#         response = server.accept(request)
#         server.send_response(response)

#         self.assertHandshakeSuccess(server)
#         self.assertNotIn("Sec-WebSocket-Extensions", response.headers)
#         self.assertEqual(server.extensions, [])

#     def test_extension(self):
#         """Server enables an extension when the client offers it."""
#         server = ServerProtocol(extensions=[ServerOpExtensionFactory()])
#         request = make_request()
#         request.headers["Sec-WebSocket-Extensions"] = "x-op; op"
#         response = server.accept(request)
#         server.send_response(response)

#         self.assertHandshakeSuccess(server)
#         self.assertEqual(response.headers["Sec-WebSocket-Extensions"], "x-op; op")
#         self.assertEqual(server.extensions, [OpExtension()])

#     def test_extension_not_enabled(self):
#         """Server doesn't enable an extension when the client doesn't offer it."""
#         server = ServerProtocol(extensions=[ServerOpExtensionFactory()])
#         request = make_request()
#         response = server.accept(request)
#         server.send_response(response)

#         self.assertHandshakeSuccess(server)
#         self.assertNotIn("Sec-WebSocket-Extensions", response.headers)
#         self.assertEqual(server.extensions, [])

#     def test_no_extensions_supported(self):
#         """Client offers an extension, but the server doesn't support any."""
#         server = ServerProtocol()
#         request = make_request()
#         request.headers["Sec-WebSocket-Extensions"] = "x-op; op"
#         response = server.accept(request)
#         server.send_response(response)

#         self.assertHandshakeSuccess(server)
#         self.assertNotIn("Sec-WebSocket-Extensions", response.headers)
#         self.assertEqual(server.extensions, [])

#     def test_extension_not_supported(self):
#         """Client offers an extension, but the server doesn't support it."""
#         server = ServerProtocol(extensions=[ServerRsv2ExtensionFactory()])
#         request = make_request()
#         request.headers["Sec-WebSocket-Extensions"] = "x-op; op"
#         response = server.accept(request)
#         server.send_response(response)

#         self.assertHandshakeSuccess(server)
#         self.assertNotIn("Sec-WebSocket-Extensions", response.headers)
#         self.assertEqual(server.extensions, [])

#     def test_supported_extension_parameters(self):
#         """Client offers an extension with parameters supported by the server."""
#         server = ServerProtocol(extensions=[ServerOpExtensionFactory("this")])
#         request = make_request()
#         request.headers["Sec-WebSocket-Extensions"] = "x-op; op=this"
#         response = server.accept(request)
#         server.send_response(response)

#         self.assertHandshakeSuccess(server)
#         self.assertEqual(response.headers["Sec-WebSocket-Extensions"], "x-op; op=this")
#         self.assertEqual(server.extensions, [OpExtension("this")])

#     def test_unsupported_extension_parameters(self):
#         """Client offers an extension with parameters unsupported by the server."""
#         server = ServerProtocol(extensions=[ServerOpExtensionFactory("this")])
#         request = make_request()
#         request.headers["Sec-WebSocket-Extensions"] = "x-op; op=that"
#         response = server.accept(request)
#         server.send_response(response)

#         self.assertHandshakeSuccess(server)
#         self.assertNotIn("Sec-WebSocket-Extensions", response.headers)
#         self.assertEqual(server.extensions, [])

#     def test_multiple_supported_extension_parameters(self):
#         """Server supports the same extension with several parameters."""
#         server = ServerProtocol(
#             extensions=[
#                 ServerOpExtensionFactory("this"),
#                 ServerOpExtensionFactory("that"),
#             ]
#         )
#         request = make_request()
#         request.headers["Sec-WebSocket-Extensions"] = "x-op; op=that"
#         response = server.accept(request)
#         server.send_response(response)

#         self.assertHandshakeSuccess(server)
#         self.assertEqual(response.headers["Sec-WebSocket-Extensions"], "x-op; op=that")
#         self.assertEqual(server.extensions, [OpExtension("that")])

#     def test_multiple_extensions(self):
#         """Server enables several extensions when the client offers them."""
#         server = ServerProtocol(
#             extensions=[ServerOpExtensionFactory(), ServerRsv2ExtensionFactory()]
#         )
#         request = make_request()
#         request.headers["Sec-WebSocket-Extensions"] = "x-op; op"
#         request.headers["Sec-WebSocket-Extensions"] = "x-rsv2"
#         response = server.accept(request)
#         server.send_response(response)

#         self.assertHandshakeSuccess(server)
#         self.assertEqual(
#             response.headers["Sec-WebSocket-Extensions"], "x-op; op, x-rsv2"
#         )
#         self.assertEqual(server.extensions, [OpExtension(), Rsv2Extension()])

#     def test_multiple_extensions_order(self):
#         """Server respects the order of extensions set in its configuration."""
#         server = ServerProtocol(
#             extensions=[ServerOpExtensionFactory(), ServerRsv2ExtensionFactory()]
#         )
#         request = make_request()
#         request.headers["Sec-WebSocket-Extensions"] = "x-rsv2"
#         request.headers["Sec-WebSocket-Extensions"] = "x-op; op"
#         response = server.accept(request)
#         server.send_response(response)

#         self.assertHandshakeSuccess(server)
#         self.assertEqual(
#             response.headers["Sec-WebSocket-Extensions"], "x-rsv2, x-op; op"
#         )
#         self.assertEqual(server.extensions, [Rsv2Extension(), OpExtension()])

#     def test_no_subprotocols(self):
#         """Handshake succeeds without subprotocols."""
#         server = ServerProtocol()
#         request = make_request()
#         response = server.accept(request)
#         server.send_response(response)

#         self.assertHandshakeSuccess(server)
#         self.assertNotIn("Sec-WebSocket-Protocol", response.headers)
#         self.assertIsNone(server.subprotocol)

#     def test_no_subprotocol_requested(self):
#         """Server expects a subprotocol, but the client doesn't offer it."""
#         server = ServerProtocol(subprotocols=["chat"])
#         request = make_request()
#         response = server.accept(request)
#         server.send_response(response)

#         self.assertEqual(response.status_code, 400)
#         self.assertHandshakeError(
#             server,
#             NegotiationError,
#             "missing subprotocol",
#         )

#     def test_subprotocol(self):
#         """Server enables a subprotocol when the client offers it."""
#         server = ServerProtocol(subprotocols=["chat"])
#         request = make_request()
#         request.headers["Sec-WebSocket-Protocol"] = "chat"
#         response = server.accept(request)
#         server.send_response(response)

#         self.assertHandshakeSuccess(server)
#         self.assertEqual(response.headers["Sec-WebSocket-Protocol"], "chat")
#         self.assertEqual(server.subprotocol, "chat")

#     def test_no_subprotocols_supported(self):
#         """Client offers a subprotocol, but the server doesn't support any."""
#         server = ServerProtocol()
#         request = make_request()
#         request.headers["Sec-WebSocket-Protocol"] = "chat"
#         response = server.accept(request)
#         server.send_response(response)

#         self.assertHandshakeSuccess(server)
#         self.assertNotIn("Sec-WebSocket-Protocol", response.headers)
#         self.assertIsNone(server.subprotocol)

#     def test_multiple_subprotocols(self):
#         """Server enables all of the subprotocols when the client offers them."""
#         server = ServerProtocol(subprotocols=["superchat", "chat"])
#         request = make_request()
#         request.headers["Sec-WebSocket-Protocol"] = "chat"
#         request.headers["Sec-WebSocket-Protocol"] = "superchat"
#         response = server.accept(request)
#         server.send_response(response)

#         self.assertHandshakeSuccess(server)
#         self.assertEqual(response.headers["Sec-WebSocket-Protocol"], "superchat")
#         self.assertEqual(server.subprotocol, "superchat")

#     def test_supported_subprotocol(self):
#         """Server enables one of the subprotocols when the client offers it."""
#         server = ServerProtocol(subprotocols=["superchat", "chat"])
#         request = make_request()
#         request.headers["Sec-WebSocket-Protocol"] = "chat"
#         response = server.accept(request)
#         server.send_response(response)

#         self.assertHandshakeSuccess(server)
#         self.assertEqual(response.headers["Sec-WebSocket-Protocol"], "chat")
#         self.assertEqual(server.subprotocol, "chat")

#     def test_unsupported_subprotocol(self):
#         """Server expects one of the subprotocols, but the client doesn't offer any."""
#         server = ServerProtocol(subprotocols=["superchat", "chat"])
#         request = make_request()
#         request.headers["Sec-WebSocket-Protocol"] = "otherchat"
#         response = server.accept(request)
#         server.send_response(response)

#         self.assertEqual(response.status_code, 400)
#         self.assertHandshakeError(
#             server,
#             NegotiationError,
#             "invalid subprotocol; expected one of superchat, chat",
#         )

#     @staticmethod
#     def optional_chat(protocol, subprotocols):
#         if "chat" in subprotocols:
#             return "chat"

#     def test_select_subprotocol(self):
#         """Server enables a subprotocol with select_subprotocol."""
#         server = ServerProtocol(select_subprotocol=self.optional_chat)
#         request = make_request()
#         request.headers["Sec-WebSocket-Protocol"] = "chat"
#         response = server.accept(request)
#         server.send_response(response)

#         self.assertHandshakeSuccess(server)
#         self.assertEqual(response.headers["Sec-WebSocket-Protocol"], "chat")
#         self.assertEqual(server.subprotocol, "chat")

#     def test_select_no_subprotocol(self):
#         """Server doesn't enable any subprotocol with select_subprotocol."""
#         server = ServerProtocol(select_subprotocol=self.optional_chat)
#         request = make_request()
#         request.headers["Sec-WebSocket-Protocol"] = "otherchat"
#         response = server.accept(request)
#         server.send_response(response)

#         self.assertHandshakeSuccess(server)
#         self.assertNotIn("Sec-WebSocket-Protocol", response.headers)
#         self.assertIsNone(server.subprotocol)


# class MiscTests(unittest.TestCase):
#     def test_bypass_handshake(self):
#         """ServerProtocol bypasses the opening handshake."""
#         server = ServerProtocol(state=OPEN)
#         server.receive_data(b"\x81\x86\x00\x00\x00\x00Hello!")
#         [frame] = server.events_received()
#         self.assertEqual(frame, Frame(OP_TEXT, b"Hello!"))

#     def test_custom_logger(self):
#         """ServerProtocol accepts a logger argument."""
#         logger = logging.getLogger("test")
#         with self.assertLogs("test", logging.DEBUG) as logs:
#             ServerProtocol(logger=logger)
#         self.assertEqual(len(logs.records), 1)


# class BackwardsCompatibilityTests(DeprecationTestCase):
#     def test_server_connection_class(self):
#         """ServerConnection is a deprecated alias for ServerProtocol."""
#         with self.assertDeprecationWarning(
#             "ServerConnection was renamed to ServerProtocol"
#         ):
#             from websockets.server import ServerConnection

#             server = ServerConnection()

#         self.assertIsInstance(server, ServerProtocol)

