from base64 import b64encode

from websockets.aliases import Bytes, MAGIC_CONSTANT
from websockets.utils.bytes import bytes_to_str
from websockets.utils.sha1 import sha1_digest_string


def ws_accept_key(key: String) -> String:
    """
    Generate the accept key for the WebSocket handshake.

    Args:
        key: The key to generate the accept key.

    Returns:
        The accept key.
    """
    var accept_key = key + MAGIC_CONSTANT
    var digest = bytes_to_str(sha1_digest_string(accept_key))

    return b64encode(digest)
