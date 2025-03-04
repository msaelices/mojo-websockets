"""
Tests for the WebSocket handshake utilities.
"""

from testing import assert_equal
from websockets.utils.handshake import ws_accept_key


fn test_websocket_accept_key() raises -> None:
    """Test generating a WebSocket accept key."""
    var client_key = "dGhlIHNhbXBsZSBub25jZQ=="  # Base64 encoded "the sample nonce"
    var expected = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

    var result = ws_accept_key(client_key)

    assert_equal(result, expected)
