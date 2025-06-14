from collections import List
from testing import assert_equal, assert_false, assert_true, assert_raises

from websockets.aliases import Bytes
from websockets.http import Header, Headers
from websockets.frames import OpCode, Frame
from websockets.http import HTTPRequest, HTTPResponse
from websockets.protocol import CONNECTING, OPEN, Event
from websockets.protocol.base import (
    close_expected,
    receive_data,
    receive_eof,
)
from websockets.protocol.client import ClientProtocol
from websockets.utils.bytes import str_to_bytes
from websockets.utils.uri import URI

from testutils import ACCEPT, KEY, assert_bytes_equal


fn date_func() -> String:
    return "Thu, 02 Jan 2025 22:16:23 GMT"


alias SOCKET_URI = "wss://example.com/test"  # for tests where the URI doesn't matter

# ===----------------------------------------------------------------------===
# Test basic opening handshake scenarios.
# ===----------------------------------------------------------------------===


fn test_send_request() raises -> None:
    """Client sends a handshake request."""
    client = ClientProtocol(uri=URI.parse(SOCKET_URI), key=String(KEY))
    request = client.connect()
    client.send_request(request)

    data_to_send = client.data_to_send()
    assert_bytes_equal(
        data_to_send,
        str_to_bytes(
            String(
                "GET /test HTTP/1.1\r\n"
                "host: example.com\r\n"
                "upgrade: websocket\r\n"
                "connection: Upgrade\r\n"
                "sec-websocket-key: {}\r\n"
                "sec-websocket-version: 13\r\n"
                "\r\n"
            ).format(KEY)
        ),
    )
    assert_false(close_expected(client))
    assert_equal(client.get_state(), CONNECTING)


fn test_receive_successful_response() raises -> None:
    """Client receives a successful handshake response."""
    client = ClientProtocol(uri=URI.parse(SOCKET_URI), key=String(KEY))
    # Receive HTTP response from the server
    receive_data(
        client,
        str_to_bytes(
            String(
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Accept: {}\r\n"
                "Date: {}\r\n"
                "\r\n"
            ).format(ACCEPT, date_func())
        ),
    )

    assert_bytes_equal(client.data_to_send(), Bytes())
    assert_false(close_expected(client))
    assert_equal(client.get_state(), OPEN)


fn test_receive_failed_response() raises -> None:
    """Client receives a failed handshake response."""
    client = ClientProtocol(uri=URI.parse(SOCKET_URI), key=String(KEY))
    # Receive HTTP response from the server
    receive_data(
        client,
        str_to_bytes(
            String(
                "HTTP/1.1 404 Not Found\r\n"
                "Date: {}\r\n"
                "Content-Length: 13\r\n"
                "Content-Type: text/plain; charset=utf-8\r\n"
                "Connection: close\r\n"
                "\r\n"
                "Sorry folks.\n"
            ).format(date_func())
        ),
    )

    assert_bytes_equal(client.data_to_send(), Bytes())
    assert_true(close_expected(client))
    assert_equal(client.get_state(), CONNECTING)


# ===----------------------------------------------------------------------===
# Test generating opening handshake requests.
# ===----------------------------------------------------------------------===


fn test_connect() raises -> None:
    """Check that connect() creates an opening handshake request."""
    client = ClientProtocol(uri=URI.parse(SOCKET_URI), key=String(KEY))
    request = client.connect()

    assert_equal(request.uri.get_path(), "/test")
    assert_equal(
        request.headers,
        Headers(
            Header("Host", "example.com"),
            Header("Upgrade", "websocket"),
            Header("Connection", "Upgrade"),
            Header("Sec-WebSocket-Key", KEY),
            Header("Sec-WebSocket-Version", "13"),
        ),
    )


fn test_path() raises -> None:
    """Check that connect() uses the path from the URI."""
    client = ClientProtocol(
        uri=URI.parse("wss://example.com/endpoint?test=1"), key=String(KEY)
    )
    request = client.connect()

    assert_equal(request.uri.get_path(), "/endpoint?test=1")


fn test_port() raises -> None:
    """Check that connect() uses the port from the URI or the default port."""
    # Handle each test case individually instead of using a list
    # Case 1
    var uri = String("ws://example.com/")
    var expected_host = String("example.com")
    var client = ClientProtocol(uri=URI.parse(uri), key=String(KEY))
    var request = client.connect()
    assert_equal(request.headers["Host"], expected_host)

    # Case 2
    uri = String("ws://example.com:80/")
    expected_host = String("example.com")
    client = ClientProtocol(uri=URI.parse(uri), key=String(KEY))
    request = client.connect()
    assert_equal(request.headers["Host"], expected_host)

    # Case 3
    uri = String("ws://example.com:8080/")
    expected_host = String("example.com:8080")
    client = ClientProtocol(uri=URI.parse(uri), key=String(KEY))
    request = client.connect()
    assert_equal(request.headers["Host"], expected_host)

    # Case 4
    uri = String("wss://example.com/")
    expected_host = String("example.com")
    client = ClientProtocol(uri=URI.parse(uri), key=String(KEY))
    request = client.connect()
    assert_equal(request.headers["Host"], expected_host)

    # Case 5
    uri = String("wss://example.com:443/")
    expected_host = String("example.com")
    client = ClientProtocol(uri=URI.parse(uri), key=String(KEY))
    request = client.connect()
    assert_equal(request.headers["Host"], expected_host)

    # Case 6
    uri = String("wss://example.com:8443/")
    expected_host = String("example.com:8443")
    client = ClientProtocol(uri=URI.parse(uri), key=String(KEY))
    request = client.connect()
    assert_equal(request.headers["Host"], expected_host)


fn test_user_info() raises -> None:
    """Check that connect() performs HTTP Basic Authentication with user info from the URI.
    """
    client = ClientProtocol(
        uri=URI.parse("wss://hello:iloveyou@example.com/"), key=String(KEY)
    )
    request = client.connect()

    assert_equal(request.headers["Authorization"], "Basic aGVsbG86aWxvdmV5b3U=")


fn test_origin() raises -> None:
    """Check that connect(origin=...) generates an Origin header."""
    client = ClientProtocol(
        uri=URI.parse(SOCKET_URI), key=String(KEY), origin=String("https://example.com")
    )
    request = client.connect()

    assert_equal(request.headers["Origin"], "https://example.com")


fn test_extensions() raises -> None:
    """Check that connect(extensions=...) generates a Sec-WebSocket-Extensions header.
    """
    # TODO: Implement once extensions are supported
    pass


fn test_subprotocols() raises -> None:
    """Check that connect(subprotocols=...) generates a Sec-WebSocket-Protocol header.
    """
    # TODO: Implement once subprotocols are supported
    pass


# ===----------------------------------------------------------------------===
# Test receiving opening handshake responses.
# ===----------------------------------------------------------------------===


fn test_receive_successful_response_with_events() raises -> None:
    """Client receives a successful handshake response and checks events."""
    client = ClientProtocol(uri=URI.parse(SOCKET_URI), key=String(KEY))

    # Receive HTTP response from the server
    receive_data(
        client,
        str_to_bytes(
            String(
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Accept: {}\r\n"
                "Date: {}\r\n"
                "\r\n"
            ).format(ACCEPT, date_func())
        ),
    )

    events = client.events_received()
    assert_equal(len(events), 1)

    response = events[0][HTTPResponse]
    assert_equal(response.status_code, 101)
    assert_equal(response.status_text, "Switching Protocols")
    assert_equal(
        response.headers,
        Headers(
            Header("Upgrade", "websocket"),
            Header("Connection", "Upgrade"),
            Header("Sec-WebSocket-Accept", ACCEPT),
            Header("Date", date_func()),
        ),
    )
    assert_bytes_equal(response.body_raw, str_to_bytes("\r\n"))


fn test_receive_failed_response_with_events() raises -> None:
    """Client receives a failed handshake response and checks events."""
    client = ClientProtocol(uri=URI.parse(SOCKET_URI), key=String(KEY))

    # Receive HTTP response from the server
    receive_data(
        client,
        str_to_bytes(
            String(
                "HTTP/1.1 404 Not Found\r\n"
                "Date: {}\r\n"
                "Content-Length: 13\r\n"
                "Content-Type: text/plain; charset=utf-8\r\n"
                "Connection: close\r\n"
                "\r\n"
                "Sorry folks.\n"
            ).format(date_func())
        ),
    )

    events = client.events_received()
    assert_equal(len(events), 1)

    response = events[0][HTTPResponse]
    assert_equal(response.status_code, 404)
    assert_equal(response.status_text, "Not Found")
    assert_equal(
        response.headers,
        Headers(
            Header("Date", date_func()),
            Header("Content-Length", "13"),
            Header("Content-Type", "text/plain; charset=utf-8"),
            Header("Connection", "close"),
        ),
    )
    assert_bytes_equal(response.body_raw, str_to_bytes("\r\nSorry folks.\n"))


fn test_receive_no_response() raises -> None:
    """Client receives no handshake response."""
    client = ClientProtocol(uri=URI.parse(SOCKET_URI), key=String(KEY))
    receive_eof(client)

    assert_equal(len(client.events_received()), 0)
    assert_true(client.get_handshake_exc())
    # Original exception in Python was:
    # EOFError: connection closed while reading HTTP status line
    assert_equal(
        String(client.get_handshake_exc().value()),
        "EOFError: connection closed before handshake completed",
    )


# TODO: Make sure it passes
# fn test_receive_truncated_response() raises -> None:
#     """Client receives a truncated handshake response."""
#     client = ClientProtocol(uri=URI.parse(SOCKET_URI), key=String(KEY))
#     receive_data(client, str_to_bytes("HTTP/1.1 101 Switching Protocols\r\n"))
#     receive_eof(client)
#
#     assert_equal(len(client.events_received()), 0)
#     assert_true(client.get_handshake_exc())
#     assert_equal(
#         String(client.get_handshake_exc().value()),
#         "EOFError: connection closed while reading HTTP headers",
#     )


fn test_receive_random_response() raises -> None:
    """Client receives a junk handshake response."""
    client = ClientProtocol(uri=URI.parse(SOCKET_URI), key=String(KEY))
    receive_data(client, str_to_bytes("220 smtp.invalid\r\n"))
    receive_data(client, str_to_bytes("250 Hello relay.invalid\r\n"))
    receive_data(client, str_to_bytes("250 Ok\r\n"))
    receive_data(client, str_to_bytes("250 Ok\r\n"))

    assert_equal(len(client.events_received()), 0)
    assert_true(client.get_handshake_exc())
    # Original exception in Python was:
    # ValueError: invalid HTTP status line: 220 smtp.invalid
    assert_equal(
        String(client.get_handshake_exc().value()),
        (
            "Failed to parse response headers: Failed to read second word from request"
            " line"
        ),
    )


# @contextlib.contextmanager
# def alter_and_receive_response(client):
#     """Generate a handshake response that can be altered for testing."""
#     # We could start by sending a handshake request, i.e.:
#     # request = client.connect()
#     # client.send_request(request)
#     # However, in the current implementation, these calls have no effect on the
#     # state of the client. Therefore, they're unnecessary and can be skipped.
#     response = Response(
#         status_code=101,
#         reason_phrase="Switching Protocols",
#         headers=Headers(
#             {
#                 "Upgrade": "websocket",
#                 "Connection": "Upgrade",
#                 "Sec-WebSocket-Accept": accept_key(client.key),
#             }
#         ),
#     )
#     yield response
#     client.receive_data(response.serialize())
#     [parsed_response] = client.events_received()
#     assert response == dataclasses.replace(parsed_response, _exception=None)


# === ------------------------------------------------------------------ ===
# Test processing of handshake responses to configure the connection.
# === ------------------------------------------------------------------ ===

#     def assertHandshakeSuccess(self, client):
#         """Assert that the opening handshake succeeded."""
#         self.assertEqual(client.state, OPEN)
#         self.assertIsNone(client.handshake_exc)

#     def assertHandshakeError(self, client, exc_type, msg):
#         """Assert that the opening handshake failed with the given exception."""
#         self.assertEqual(client.state, CONNECTING)
#         self.assertIsInstance(client.handshake_exc, exc_type)
#         # Exception chaining isn't used is client handshake implementation.
#         assert client.handshake_exc.__cause__ is None
#         self.assertEqual(String(client.handshake_exc), msg)


fn test_basic() raises -> None:
    """Handshake succeeds."""
    client = ClientProtocol(uri=URI.parse(SOCKET_URI), key=String(KEY))

    # Receive HTTP response from the server
    receive_data(
        client,
        str_to_bytes(
            String(
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Accept: {}\r\n"
                "Date: {}\r\n"
                "\r\n"
            ).format(ACCEPT, date_func())
        ),
    )

    assert_equal(client.get_state(), OPEN)
    assert_false(client.get_handshake_exc())


fn test_missing_connection() raises -> None:
    """Handshake fails when the Connection header is missing."""
    client = ClientProtocol(uri=URI.parse(SOCKET_URI), key=String(KEY))

    # Receive HTTP response from the server with missing Connection header
    receive_data(
        client,
        str_to_bytes(
            String(
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Sec-WebSocket-Accept: {}\r\n"
                "Date: {}\r\n"
                "\r\n"
            ).format(ACCEPT, date_func())
        ),
    )

    assert_equal(client.get_state(), CONNECTING)
    assert_true(client.get_handshake_exc())
    assert_equal(
        String(client.get_handshake_exc().value()),
        'InvalidHeader: Missing "Connection" header',
    )


fn test_invalid_connection() raises -> None:
    """Handshake fails when the Connection header is invalid."""
    client = ClientProtocol(uri=URI.parse(SOCKET_URI), key=String(KEY))

    # Receive HTTP response from the server with invalid Connection header
    receive_data(
        client,
        str_to_bytes(
            String(
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: close\r\n"
                "Sec-WebSocket-Accept: {}\r\n"
                "Date: {}\r\n"
                "\r\n"
            ).format(ACCEPT, date_func())
        ),
    )

    assert_equal(client.get_state(), CONNECTING)
    assert_true(client.get_handshake_exc())
    # Original exception in Python was:
    # InvalidHeader: Invalid "Connection" header: close
    assert_equal(
        String(client.get_handshake_exc().value()),
        'InvalidUpgrade: Response "Connection" header is not "Upgrade"',
    )


fn test_missing_upgrade() raises -> None:
    """Handshake fails when the Upgrade header is missing."""
    client = ClientProtocol(uri=URI.parse(SOCKET_URI), key=String(KEY))

    # Receive HTTP response from the server with missing Upgrade header
    receive_data(
        client,
        str_to_bytes(
            String(
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Accept: {}\r\n"
                "Date: {}\r\n"
                "\r\n"
            ).format(ACCEPT, date_func())
        ),
    )

    assert_equal(client.get_state(), CONNECTING)
    assert_true(client.get_handshake_exc())
    assert_equal(
        String(client.get_handshake_exc().value()),
        'InvalidHeader: Missing "Upgrade" header',
    )


fn test_invalid_upgrade() raises -> None:
    """Handshake fails when the Upgrade header is invalid."""
    client = ClientProtocol(uri=URI.parse(SOCKET_URI), key=String(KEY))

    # Receive HTTP response from the server with invalid Upgrade header
    receive_data(
        client,
        str_to_bytes(
            String(
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: h2c\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Accept: {}\r\n"
                "Date: {}\r\n"
                "\r\n"
            ).format(ACCEPT, date_func())
        ),
    )

    assert_equal(client.get_state(), CONNECTING)
    assert_true(client.get_handshake_exc())
    assert_equal(
        String(client.get_handshake_exc().value()),
        'InvalidUpgrade: Response "Upgrade" header is not "websocket"',
    )


fn test_missing_accept() raises -> None:
    """Handshake fails when the Sec-WebSocket-Accept header is missing."""
    client = ClientProtocol(uri=URI.parse(SOCKET_URI), key=String(KEY))

    # Receive HTTP response from the server with missing Sec-WebSocket-Accept header
    receive_data(
        client,
        str_to_bytes(
            String(
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Date: {}\r\n"
                "\r\n"
            ).format(date_func())
        ),
    )

    assert_equal(client.get_state(), CONNECTING)
    assert_true(client.get_handshake_exc())
    assert_equal(
        String(client.get_handshake_exc().value()),
        'InvalidHeader: Missing "Sec-WebSocket-Accept" header',
    )


# TODO: Implement multiple accept logic in the future
# fn test_multiple_accept() raises -> None:
#     """Handshake fails when the Sec-WebSocket-Accept header is repeated."""
#     client = ClientProtocol(uri=URI.parse(SOCKET_URI), key=String(KEY))
#
#     # Receive HTTP response from the server with repeated Sec-WebSocket-Accept header
#     receive_data(
#         client,
#         str_to_bytes(
#             "HTTP/1.1 101 Switching Protocols\r\n"
#             "Upgrade: websocket\r\n"
#             "Connection: Upgrade\r\n"
#             "Sec-WebSocket-Accept: {}\r\n"
#             "Sec-WebSocket-Accept: {}\r\n"
#             "Date: {}\r\n"
#             "\r\n".format(ACCEPT, ACCEPT, date_func())
#         ),
#     )
#
#     assert_equal(client.get_state(), CONNECTING)
#     assert_true(client.get_handshake_exc())
#     assert_equal(
#         String(client.get_handshake_exc().value()),
#         'InvalidHeader: Multiple "Sec-WebSocket-Accept" headers'
#     )


fn test_invalid_accept() raises -> None:
    """Handshake fails when the Sec-WebSocket-Accept header is invalid."""
    client = ClientProtocol(uri=URI.parse(SOCKET_URI), key=String(KEY))

    # Receive HTTP response from the server with invalid Sec-WebSocket-Accept header
    receive_data(
        client,
        str_to_bytes(
            String(
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Accept: invalid_accept_key\r\n"
                "Date: {}\r\n"
                "\r\n"
            ).format(date_func())
        ),
    )

    assert_equal(client.get_state(), CONNECTING)
    assert_true(client.get_handshake_exc())
    assert_equal(
        String(client.get_handshake_exc().value()),
        'InvalidHeader: "Sec-WebSocket-Accept" header is invalid',
    )


# fn test_close_reason_not_provided() raises:
#     """Test handling when no close reason is provided."""
#     client = DummyProtocol[False, CLIENT](OPEN, StreamReader(), Bytes(), List[Event]())
#     receive_data(client, Bytes(136, 0))  # \x88\x00
#     events = client.events_received()
#     assert_equal(events[0][Frame], Frame(OpCode.OP_CLOSE, Bytes(), fin=True))


fn test_bypass_handshake() raises -> None:
    """ClientProtocol bypasses the opening handshake if state is OPEN."""
    client = ClientProtocol(uri=URI.parse(SOCKET_URI), key=String(KEY))
    client.set_state(OPEN)
    receive_data(client, str_to_bytes("\x81\x06Hello!"))

    events = client.events_received()

    assert_true(events[0].isa[Frame]())
    assert_bytes_equal(
        events[0][Frame].data, Frame(OpCode.OP_TEXT, str_to_bytes("Hello!")).data
    )


# TODO: Implement this tests when extensions are supported
#     def test_no_extensions(self):
#         """Handshake succeeds without extensions."""
#         client = ClientProtocol(URI)
#         with alter_and_receive_response(client):
#             pass

#         self.assertHandshakeSuccess(client)
#         self.assertEqual(client.extensions, [])

#     def test_offer_extension(self):
#         """Client offers an extension."""
#         client = ClientProtocol(URI, extensions=[ClientRsv2ExtensionFactory()])
#         request = client.connect()

#         self.assertEqual(request.headers["Sec-WebSocket-Extensions"], "x-rsv2")

#     def test_enable_extension(self):
#         """Client offers an extension and the server enables it."""
#         client = ClientProtocol(URI, extensions=[ClientRsv2ExtensionFactory()])
#         with alter_and_receive_response(client) as response:
#             response.headers["Sec-WebSocket-Extensions"] = "x-rsv2"

#         self.assertHandshakeSuccess(client)
#         self.assertEqual(client.extensions, [Rsv2Extension()])

#     def test_extension_not_enabled(self):
#         """Client offers an extension, but the server doesn't enable it."""
#         client = ClientProtocol(URI, extensions=[ClientRsv2ExtensionFactory()])
#         with alter_and_receive_response(client):
#             pass

#         self.assertHandshakeSuccess(client)
#         self.assertEqual(client.extensions, [])

#     def test_no_extensions_offered(self):
#         """Server enables an extension when the client didn't offer any."""
#         client = ClientProtocol(URI)
#         with alter_and_receive_response(client) as response:
#             response.headers["Sec-WebSocket-Extensions"] = "x-rsv2"

#         self.assertHandshakeError(
#             client,
#             InvalidHandshake,
#             "no extensions supported",
#         )

#     def test_extension_not_offered(self):
#         """Server enables an extension that the client didn't offer."""
#         client = ClientProtocol(URI, extensions=[ClientRsv2ExtensionFactory()])
#         with alter_and_receive_response(client) as response:
#             response.headers["Sec-WebSocket-Extensions"] = "x-op; op"

#         self.assertHandshakeError(
#             client,
#             InvalidHandshake,
#             "Unsupported extension: name = x-op, params = [('op', None)]",
#         )

#     def test_supported_extension_parameters(self):
#         """Server enables an extension with parameters supported by the client."""
#         client = ClientProtocol(URI, extensions=[ClientOpExtensionFactory("this")])
#         with alter_and_receive_response(client) as response:
#             response.headers["Sec-WebSocket-Extensions"] = "x-op; op=this"

#         self.assertHandshakeSuccess(client)
#         self.assertEqual(client.extensions, [OpExtension("this")])

#     def test_unsupported_extension_parameters(self):
#         """Server enables an extension with parameters unsupported by the client."""
#         client = ClientProtocol(URI, extensions=[ClientOpExtensionFactory("this")])
#         with alter_and_receive_response(client) as response:
#             response.headers["Sec-WebSocket-Extensions"] = "x-op; op=that"

#         self.assertHandshakeError(
#             client,
#             InvalidHandshake,
#             "Unsupported extension: name = x-op, params = [('op', 'that')]",
#         )

#     def test_multiple_supported_extension_parameters(self):
#         """Client offers the same extension with several parameters."""
#         client = ClientProtocol(
#             URI,
#             extensions=[
#                 ClientOpExtensionFactory("this"),
#                 ClientOpExtensionFactory("that"),
#             ],
#         )
#         with alter_and_receive_response(client) as response:
#             response.headers["Sec-WebSocket-Extensions"] = "x-op; op=that"

#         self.assertHandshakeSuccess(client)
#         self.assertEqual(client.extensions, [OpExtension("that")])

#     def test_multiple_extensions(self):
#         """Client offers several extensions and the server enables them."""
#         client = ClientProtocol(
#             URI,
#             extensions=[
#                 ClientOpExtensionFactory(),
#                 ClientRsv2ExtensionFactory(),
#             ],
#         )
#         with alter_and_receive_response(client) as response:
#             response.headers["Sec-WebSocket-Extensions"] = "x-op; op"
#             response.headers["Sec-WebSocket-Extensions"] = "x-rsv2"

#         self.assertHandshakeSuccess(client)
#         self.assertEqual(client.extensions, [OpExtension(), Rsv2Extension()])

#     def test_multiple_extensions_order(self):
#         """Client respects the order of extensions chosen by the server."""
#         client = ClientProtocol(
#             URI,
#             extensions=[
#                 ClientOpExtensionFactory(),
#                 ClientRsv2ExtensionFactory(),
#             ],
#         )
#         with alter_and_receive_response(client) as response:
#             response.headers["Sec-WebSocket-Extensions"] = "x-rsv2"
#             response.headers["Sec-WebSocket-Extensions"] = "x-op; op"

#         self.assertHandshakeSuccess(client)
#         self.assertEqual(client.extensions, [Rsv2Extension(), OpExtension()])

# TODO: Implement this tests when subprotocols are supported
#     def test_no_subprotocols(self):
#         """Handshake succeeds without subprotocols."""
#         client = ClientProtocol(URI)
#         with alter_and_receive_response(client):
#             pass

#         self.assertHandshakeSuccess(client)
#         self.assertIsNone(client.subprotocol)

#     def test_no_subprotocol_requested(self):
#         """Client doesn't offer a subprotocol, but the server enables one."""
#         client = ClientProtocol(URI)
#         with alter_and_receive_response(client) as response:
#             response.headers["Sec-WebSocket-Protocol"] = "chat"

#         self.assertHandshakeError(
#             client,
#             InvalidHandshake,
#             "no subprotocols supported",
#         )

#     def test_offer_subprotocol(self):
#         """Client offers a subprotocol."""
#         client = ClientProtocol(URI, subprotocols=["chat"])
#         request = client.connect()

#         self.assertEqual(request.headers["Sec-WebSocket-Protocol"], "chat")

#     def test_enable_subprotocol(self):
#         """Client offers a subprotocol and the server enables it."""
#         client = ClientProtocol(URI, subprotocols=["chat"])
#         with alter_and_receive_response(client) as response:
#             response.headers["Sec-WebSocket-Protocol"] = "chat"

#         self.assertHandshakeSuccess(client)
#         self.assertEqual(client.subprotocol, "chat")

#     def test_no_subprotocol_accepted(self):
#         """Client offers a subprotocol, but the server doesn't enable it."""
#         client = ClientProtocol(URI, subprotocols=["chat"])
#         with alter_and_receive_response(client):
#             pass

#         self.assertHandshakeSuccess(client)
#         self.assertIsNone(client.subprotocol)

#     def test_multiple_subprotocols(self):
#         """Client offers several subprotocols and the server enables one."""
#         client = ClientProtocol(URI, subprotocols=["superchat", "chat"])
#         with alter_and_receive_response(client) as response:
#             response.headers["Sec-WebSocket-Protocol"] = "chat"

#         self.assertHandshakeSuccess(client)
#         self.assertEqual(client.subprotocol, "chat")

#     def test_unsupported_subprotocol(self):
#         """Client offers subprotocols but the server enables another one."""
#         client = ClientProtocol(URI, subprotocols=["superchat", "chat"])
#         with alter_and_receive_response(client) as response:
#             response.headers["Sec-WebSocket-Protocol"] = "otherchat"

#         self.assertHandshakeError(
#             client,
#             InvalidHandshake,
#             "unsupported subprotocol: otherchat",
#         )

#     def test_multiple_subprotocols_accepted(self):
#         """Server attempts to enable multiple subprotocols."""
#         client = ClientProtocol(URI, subprotocols=["superchat", "chat"])
#         with alter_and_receive_response(client) as response:
#             response.headers["Sec-WebSocket-Protocol"] = "superchat"
#             response.headers["Sec-WebSocket-Protocol"] = "chat"

#         self.assertHandshakeError(
#             client,
#             InvalidHandshake,
#             "invalid Sec-WebSocket-Protocol header: "
#             "multiple values: superchat, chat",
#         )


#     def test_custom_logger(self):
#         """ClientProtocol accepts a logger argument."""
#         logger = logging.getLogger("test")
#         with self.assertLogs("test", logging.DEBUG) as logs:
#             ClientProtocol(URI, logger=logger)
#         self.assertEqual(len(logs.records), 1)


# class BackwardsCompatibilityTests(DeprecationTestCase):
#     def test_client_connection_class(self):
#         """ClientConnection is a deprecated alias for ClientProtocol."""
#         with self.assertDeprecationWarning(
#             "ClientConnection was renamed to ClientProtocol"
#         ):
#             from websockets.client import ClientConnection

#             client = ClientConnection("ws://localhost/")

#         self.assertIsInstance(client, ClientProtocol)


# class BackoffTests(unittest.TestCase):
#     def test_backoff(self):
#         """backoff() yields a random delay, then exponentially increasing delays."""
#         backoff_gen = backoff()
#         self.assertIsInstance(backoff_gen, types.GeneratorType)

#         initial_delay = next(backoff_gen)
#         self.assertGreaterEqual(initial_delay, 0)
#         self.assertLess(initial_delay, 5)

#         following_delays = [int(next(backoff_gen)) for _ in range(9)]
#         self.assertEqual(following_delays, [3, 5, 8, 13, 21, 34, 55, 89, 90])
