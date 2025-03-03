from base64 import b64encode

from websockets.aliases import Bytes, MAGIC_CONSTANT
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

    var digest = sha1_digest_string(accept_key)

    # Convert digest to Bytes for b64encode
    var s = Bytes(capacity=len(digest))
    for i in range(len(digest)):
        s.append(Int(digest[i]))

    return b64encode(s)
