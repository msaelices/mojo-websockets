from base64 import b64encode
from python import Python, PythonObject

from ..aliases import MAGIC_CONSTANT


def ws_accept_key(key: String) -> String:
    """
    Generate the accept key for the WebSocket handshake.

    Args:
        key: The key to generate the accept key.

    Returns:
        The accept key.
    """
    var accept_key = key + MAGIC_CONSTANT
    var py_sha1 = Python.import_module("hashlib").sha1

    var encoded_key = str(py_sha1(PythonObject(accept_key).encode()).digest())
    return b64encode(encoded_key)
